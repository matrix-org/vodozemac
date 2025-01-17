// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cmp::Ordering;

use aes::cipher::block_padding::UnpadError;
use hmac::digest::MacError;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::{
    default_config,
    message::MegolmMessage,
    ratchet::Ratchet,
    session_config::Version,
    session_keys::{ExportedSessionKey, SessionKey},
    GroupSession, SessionConfig,
};
use crate::{
    cipher::{Cipher, Mac, MessageMac},
    types::{Ed25519PublicKey, SignatureError},
    utilities::{base64_encode, pickle, unpickle},
    PickleError,
};

/// The result of a comparison between two [`InboundGroupSession`] types.
///
/// Tells us if one session can be considered to be better than another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOrdering {
    /// The sessions are the same.
    Equal,
    /// The first session has a better initial message index than the second
    /// one.
    Better,
    /// The first session has a worse initial message index than the second one.
    Worse,
    /// The sessions are not the same, they can't be compared.
    Unconnected,
}

/// Error type for Megolm-based decryption failures.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// The signature on the message was invalid.
    #[error("The signature on the message was invalid: {0}")]
    Signature(#[from] SignatureError),

    /// The message authentication code of the message was invalid.
    #[error("Failed decrypting Megolm message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),

    /// The length of the message authentication code of the message did not
    /// match our expected length.
    #[error("Failed decrypting Olm message, invalid MAC length: expected {0}, got {1}")]
    InvalidMACLength(usize, usize),

    /// The ciphertext of the message isn't padded correctly.
    #[error("Failed decrypting Megolm message, invalid padding")]
    InvalidPadding(#[from] UnpadError),

    /// The session is missing the correct message key to decrypt the message,
    /// The Session has been ratcheted forwards and the message key isn't
    /// available anymore.
    #[error(
        "The message was encrypted using an unknown message index, \
        first known index {0}, index of the message {1}"
    )]
    UnknownMessageIndex(u32, u32),
}

/// A Megolm inbound group session represents a single receiving participant in
/// an encrypted group communication involving multiple recipients.
///
/// The session includes a ratchet for decryption and an Ed25519 public key for
/// ensuring authenticity.
#[derive(Deserialize)]
#[serde(try_from = "InboundGroupSessionPickle")]
pub struct InboundGroupSession {
    initial_ratchet: Ratchet,
    latest_ratchet: Ratchet,
    signing_key: Ed25519PublicKey,
    signing_key_verified: bool,
    config: SessionConfig,
}

/// A message successfully decrypted by an [`InboundGroupSession`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedMessage {
    /// The decrypted plaintext of the message.
    pub plaintext: Vec<u8>,
    /// The message index, used to detect replay attacks. Each plaintext message
    /// should be encrypted with a unique message index per session.
    pub message_index: u32,
}

impl InboundGroupSession {
    /// Creates a new [`InboundGroupSession`] from a [`SessionKey`] received
    /// over an authenticated channel.
    ///
    /// A [`SessionKey`] can be obtained from the sender's [`GroupSession`]
    /// using the [`GroupSession::session_key()`] method.
    pub fn new(key: &SessionKey, session_config: SessionConfig) -> Self {
        let initial_ratchet =
            Ratchet::from_bytes(key.session_key.ratchet.clone(), key.session_key.ratchet_index);
        let latest_ratchet = initial_ratchet.clone();

        Self {
            initial_ratchet,
            latest_ratchet,
            signing_key: key.session_key.signing_key,
            signing_key_verified: true,
            config: session_config,
        }
    }

    /// Creates a new [`InboundGroupSession`] from an [`ExportedSessionKey`]
    /// received over an authenticated channel.
    ///
    /// An [`ExportedSessionKey`] can be obtained from another recipient's
    /// [`InboundGroupSession`] using the [`InboundGroupSession::export_at()`]
    /// method.
    ///
    /// **Warning**: Extra care is required to ensure the authenticity of the
    /// [`InboundGroupSession`] because an [`ExportedSessionKey`] does not
    /// include the signature of the original [`GroupSession`] creator.
    pub fn import(session_key: &ExportedSessionKey, session_config: SessionConfig) -> Self {
        let initial_ratchet =
            Ratchet::from_bytes(session_key.ratchet.clone(), session_key.ratchet_index);
        let latest_ratchet = initial_ratchet.clone();

        Self {
            initial_ratchet,
            latest_ratchet,
            signing_key: session_key.signing_key,
            signing_key_verified: false,
            config: session_config,
        }
    }

    /// Retrieves the unique ID of this session.
    ///
    /// This ID is the [`Ed25519PublicKey`] encoded in Base64 format.
    pub fn session_id(&self) -> String {
        base64_encode(self.signing_key.as_bytes())
    }

    /// Check if two [`InboundGroupSession`]s are the same.
    ///
    /// An [`InboundGroupSession`] could be received multiple times with varying
    /// degrees of trust and first known message indices.
    ///
    /// This method checks if the underlying ratchets of the two
    /// [`InboundGroupSession`]s are actually the same ratchet, potentially at
    /// a different ratcheting index. That is, if the sessions are *connected*,
    /// then ratcheting one of the ratchets to the index of the other should
    /// yield the same ratchet value, byte-for-byte. This will only be the case
    /// if the [`InboundGroupSession`]s were created from the same
    /// [`GroupSession`].
    ///
    /// If the sessions are connected, the session with the lower message index
    /// can safely replace the one with the higher message index.
    pub fn connected(&mut self, other: &mut InboundGroupSession) -> bool {
        // This method attempts to bring the two `Ratchet` values, one from each
        // session, to the same message index.
        //
        // We first try to ratchet our own ratchets towards the initial ratchet
        // of the other session. If that fails we try to ratchet the other
        // session's ratchets towards our initial ratchet.
        //
        // After that we compare the raw ratchet bytes in constant time.

        #[allow(clippy::unreachable)]
        if self.config != other.config || self.signing_key != other.signing_key {
            // Short circuit if session configs differ or the signing keys
            // differ. This is comparing public key material.
            false
        } else if let Some(ratchet) = self.find_ratchet(other.first_known_index()) {
            ratchet.ct_eq(&other.initial_ratchet).into()
        } else if let Some(ratchet) = other.find_ratchet(self.first_known_index()) {
            self.initial_ratchet.ct_eq(ratchet).into()
        } else {
            unreachable!("Either index A >= index B, or vice versa. There is no third option.")
        }
    }

    /// Compare the [`InboundGroupSession`] with the given other
    /// [`InboundGroupSession`].
    ///
    /// Returns a [`SessionOrdering`] describing how the two sessions relate to
    /// each other.
    pub fn compare(&mut self, other: &mut InboundGroupSession) -> SessionOrdering {
        if self.connected(other) {
            match self.first_known_index().cmp(&other.first_known_index()) {
                Ordering::Less => SessionOrdering::Better,
                Ordering::Equal => SessionOrdering::Equal,
                Ordering::Greater => SessionOrdering::Worse,
            }
        } else {
            // If we're not connected to other, other can't be better.
            SessionOrdering::Unconnected
        }
    }

    /// Merge the session with the given other session, picking the best parts
    /// from each of them.
    ///
    /// This method is useful when you receive multiple sessions with
    /// the same session ID but potentially different ratchet indices and
    /// authenticity properties.
    ///
    /// For example, imagine you receive a `SessionKey` S1 with ratchet index
    /// A from a fully-trusted source and an `ExportedSessionKey` S2 with
    /// ratchet state B from a less trusted source. If A > B, then S1 is better
    /// because it's fully trusted, but worse because it's ratcheted further
    /// than S2.
    ///
    /// This method allows you to merge S1 and S2 safely into a fully-trusted S3
    /// with ratchet state B, provided S1 and S2 connect with each other
    /// (meaning they are the same session, just at different ratchet indices).
    ///
    /// Returns `Some(session)` if the sessions could be merged, i.e. they are
    /// considered to be connected and `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use vodozemac::megolm::{GroupSession, InboundGroupSession, SessionOrdering};
    ///
    /// let session = GroupSession::new(Default::default());
    /// let session_key = session.session_key();
    ///
    /// let mut first_session = InboundGroupSession::new(&session_key, Default::default());
    /// let mut second_session = InboundGroupSession::import(&first_session.export_at(10).unwrap(), Default::default());
    ///
    /// assert_eq!(first_session.compare(&mut second_session), SessionOrdering::Better);
    ///
    /// let mut merged = second_session.merge(&mut first_session).unwrap();
    ///
    /// assert_eq!(merged.compare(&mut second_session), SessionOrdering::Better);
    /// assert_eq!(merged.compare(&mut first_session), SessionOrdering::Equal);
    /// ```
    pub fn merge(&mut self, other: &mut InboundGroupSession) -> Option<InboundGroupSession> {
        let best_ratchet = match self.compare(other) {
            SessionOrdering::Equal | SessionOrdering::Better => Some(self.initial_ratchet.clone()),
            SessionOrdering::Worse => Some(other.initial_ratchet.clone()),
            SessionOrdering::Unconnected => None,
        }?;

        Some(InboundGroupSession {
            initial_ratchet: best_ratchet.clone(),
            latest_ratchet: best_ratchet,
            signing_key: self.signing_key,
            signing_key_verified: self.signing_key_verified || other.signing_key_verified,
            config: self.config,
        })
    }

    /// Retrieves the first known message index for this
    /// [`InboundGroupSession`].
    ///
    /// The message index reflects how many times the ratchet has advanced,
    /// determining which messages the [`InboundGroupSession`] can decrypt.
    /// For example, if the first known index is zero, the session
    /// can decrypt all messages encrypted by the [`GroupSession`]. If the index
    /// is one, it can decrypt all messages except the first (zeroth) one.
    pub const fn first_known_index(&self) -> u32 {
        self.initial_ratchet.index()
    }

    /// Permanently advances the session to the specified message index.
    ///
    /// Advancing the [`InboundGroupSession`] will remove the ability to decrypt
    /// messages encrypted with a lower index than the provided one.
    ///
    /// Returns `true` if the ratchet was successfully advanced, or `false` if
    /// the ratchet was already advanced beyond the given index.
    pub fn advance_to(&mut self, index: u32) -> bool {
        if self.first_known_index() < index {
            self.initial_ratchet.advance_to(index);

            if self.latest_ratchet.index() < index {
                self.latest_ratchet = self.initial_ratchet.clone();
            }

            true
        } else {
            false
        }
    }

    /// Returns a copy of the [`Cipher`] at the given message index, without
    /// advancing the internal ratchets.
    #[cfg(feature = "low-level-api")]
    pub fn get_cipher_at(&self, message_index: u32) -> Option<Cipher> {
        if self.initial_ratchet.index() <= message_index {
            let mut ratchet = self.initial_ratchet.clone();
            if self.initial_ratchet.index() < message_index {
                ratchet.advance_to(message_index);
            }
            Some(Cipher::new_megolm(ratchet.as_bytes()))
        } else {
            None
        }
    }

    fn find_ratchet(&mut self, message_index: u32) -> Option<&Ratchet> {
        if self.initial_ratchet.index() == message_index {
            Some(&self.initial_ratchet)
        } else if self.latest_ratchet.index() == message_index {
            Some(&self.latest_ratchet)
        } else if self.latest_ratchet.index() < message_index {
            self.latest_ratchet.advance_to(message_index);
            Some(&self.latest_ratchet)
        } else if self.initial_ratchet.index() < message_index {
            self.latest_ratchet = self.initial_ratchet.clone();
            self.latest_ratchet.advance_to(message_index);
            Some(&self.latest_ratchet)
        } else {
            None
        }
    }

    fn verify_mac(&self, cipher: &Cipher, message: &MegolmMessage) -> Result<(), DecryptionError> {
        match self.config.version {
            Version::V1 => {
                if let MessageMac::Truncated(m) = &message.mac {
                    Ok(cipher.verify_truncated_mac(&message.to_mac_bytes(), m)?)
                } else {
                    Err(DecryptionError::InvalidMACLength(Mac::TRUNCATED_LEN, Mac::LENGTH))
                }
            }
            Version::V2 => {
                if let MessageMac::Full(m) = &message.mac {
                    Ok(cipher.verify_mac(&message.to_mac_bytes(), m)?)
                } else {
                    Err(DecryptionError::InvalidMACLength(Mac::LENGTH, Mac::TRUNCATED_LEN))
                }
            }
        }
    }

    /// Decrypts the provided [`MegolmMessage`] using this
    /// [`InboundGroupSession`].
    ///
    /// Returns a [`DecryptedMessage`] containing the plaintext and the message
    /// index, which indicates the ratchet position at which the message was
    /// encrypted.
    pub fn decrypt(
        &mut self,
        message: &MegolmMessage,
    ) -> Result<DecryptedMessage, DecryptionError> {
        self.signing_key.verify(&message.to_signature_bytes(), &message.signature)?;

        if let Some(ratchet) = self.find_ratchet(message.message_index) {
            let cipher = Cipher::new_megolm(ratchet.as_bytes());

            self.verify_mac(&cipher, message)?;

            let plaintext = cipher.decrypt(&message.ciphertext)?;

            Ok(DecryptedMessage { plaintext, message_index: message.message_index })
        } else {
            Err(DecryptionError::UnknownMessageIndex(
                self.initial_ratchet.index(),
                message.message_index,
            ))
        }
    }

    /// Export the [`InboundGroupSession`] at the specified message index.
    ///
    /// The message index indicates how many times the ratchet has advanced,
    /// which determines the messages the [`InboundGroupSession`] can
    /// decrypt. For example, if the first known index is zero, the session
    /// can decrypt all messages encrypted by the [`GroupSession`]. If the index
    /// is one, it can decrypt all messages except the first (zeroth) one.
    ///
    /// Returns `None` if the [`InboundGroupSession`] has been ratcheted beyond
    /// the given index, otherwise `None`.
    ///
    /// This method can be used to forget a certain amount of message keys to
    /// remove the ability to decrypt those messages.
    pub fn export_at(&mut self, index: u32) -> Option<ExportedSessionKey> {
        let signing_key = self.signing_key;

        self.find_ratchet(index).map(|ratchet| ExportedSessionKey::new(ratchet, signing_key))
    }

    /// Exports the [`InboundGroupSession`] at its first known message index.
    ///
    /// This is equivalent to passing the message index from
    /// [`InboundGroupSession::first_known_index()`] to the
    /// [`InboundGroupSession::export_at()`] method. Since exporting at the
    /// first known index is always possible, this function cannot fail.
    pub fn export_at_first_known_index(&self) -> ExportedSessionKey {
        ExportedSessionKey::new(&self.initial_ratchet, self.signing_key)
    }

    /// Convert the inbound group session into a struct which implements
    /// [`serde::Serialize`] and [`serde::Deserialize`].
    pub fn pickle(&self) -> InboundGroupSessionPickle {
        InboundGroupSessionPickle {
            initial_ratchet: self.initial_ratchet.clone(),
            signing_key: self.signing_key,
            signing_key_verified: self.signing_key_verified,
            config: self.config,
        }
    }

    /// Restore an [`InboundGroupSession`] from a previously saved
    /// [`InboundGroupSessionPickle`].
    pub fn from_pickle(pickle: InboundGroupSessionPickle) -> Self {
        Self::from(pickle)
    }

    /// Creates a [`InboundGroupSession`] object by unpickling a session in the
    /// legacy libolm pickle format.
    ///
    /// These pickles are encrypted and must be decrypted using the provided
    /// `pickle_key`.
    #[cfg(feature = "libolm-compat")]
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, crate::LibolmPickleError> {
        use crate::{
            megolm::inbound_group_session::libolm_compat::Pickle, utilities::unpickle_libolm,
        };

        const PICKLE_VERSION: u32 = 2;
        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
    }
}

#[cfg(feature = "libolm-compat")]
mod libolm_compat {
    use matrix_pickle::Decode;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::InboundGroupSession;
    use crate::{
        megolm::{libolm::LibolmRatchetPickle, SessionConfig},
        Ed25519PublicKey,
    };

    #[derive(Zeroize, ZeroizeOnDrop, Decode)]
    pub(super) struct Pickle {
        version: u32,
        initial_ratchet: LibolmRatchetPickle,
        latest_ratchet: LibolmRatchetPickle,
        signing_key: [u8; 32],
        signing_key_verified: bool,
    }

    impl TryFrom<Pickle> for InboundGroupSession {
        type Error = crate::LibolmPickleError;

        fn try_from(pickle: Pickle) -> Result<Self, Self::Error> {
            // Removing the borrow doesn't work and clippy complains about
            // this on nightly.
            #[allow(clippy::needless_borrow)]
            let initial_ratchet = (&pickle.initial_ratchet).into();
            #[allow(clippy::needless_borrow)]
            let latest_ratchet = (&pickle.latest_ratchet).into();
            let signing_key = Ed25519PublicKey::from_slice(&pickle.signing_key)?;
            let signing_key_verified = pickle.signing_key_verified;

            Ok(Self {
                initial_ratchet,
                latest_ratchet,
                signing_key,
                signing_key_verified,
                config: SessionConfig::version_1(),
            })
        }
    }
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling
/// [`InboundGroupSession::pickle`].
#[derive(Serialize, Deserialize)]
pub struct InboundGroupSessionPickle {
    initial_ratchet: Ratchet,
    signing_key: Ed25519PublicKey,
    #[allow(dead_code)]
    signing_key_verified: bool,
    #[serde(default = "default_config")]
    config: SessionConfig,
}

impl InboundGroupSessionPickle {
    /// Serialize and encrypt the pickle using the given key.
    ///
    /// This is the inverse of [`InboundGroupSessionPickle::from_encrypted`].
    pub fn encrypt(self, pickle_key: &[u8; 32]) -> String {
        pickle(&self, pickle_key)
    }

    /// Obtain a pickle from a ciphertext by decrypting and deserializing using
    /// the given key.
    ///
    /// This is the inverse of [`InboundGroupSessionPickle::encrypt`].
    pub fn from_encrypted(ciphertext: &str, pickle_key: &[u8; 32]) -> Result<Self, PickleError> {
        unpickle(ciphertext, pickle_key)
    }
}

impl From<&InboundGroupSession> for InboundGroupSessionPickle {
    fn from(session: &InboundGroupSession) -> Self {
        session.pickle()
    }
}

impl From<InboundGroupSessionPickle> for InboundGroupSession {
    fn from(pickle: InboundGroupSessionPickle) -> Self {
        Self {
            initial_ratchet: pickle.initial_ratchet.clone(),
            latest_ratchet: pickle.initial_ratchet,
            signing_key: pickle.signing_key,
            signing_key_verified: pickle.signing_key_verified,
            config: pickle.config,
        }
    }
}

impl From<&GroupSession> for InboundGroupSession {
    fn from(session: &GroupSession) -> Self {
        Self::new(&session.session_key(), session.session_config())
    }
}

#[cfg(test)]
mod test {
    use olm_rs::outbound_group_session::OlmOutboundGroupSession;

    use super::InboundGroupSession;
    use crate::{
        cipher::Cipher,
        megolm::{GroupSession, SessionConfig, SessionKey, SessionOrdering},
    };

    #[test]
    fn advance_inbound_session() {
        let mut session = InboundGroupSession::from(&GroupSession::new(Default::default()));

        assert_eq!(session.first_known_index(), 0);
        assert_eq!(session.latest_ratchet.index(), 0);

        assert!(session.advance_to(10));
        assert_eq!(session.first_known_index(), 10);
        assert_eq!(session.latest_ratchet.index(), 10);

        assert!(!session.advance_to(10));

        assert!(session.advance_to(20));
        assert_eq!(session.first_known_index(), 20);
        assert_eq!(session.latest_ratchet.index(), 20);
    }

    #[test]
    fn connecting() {
        let outbound = GroupSession::new(Default::default());
        let mut session = InboundGroupSession::from(&outbound);
        let mut clone = InboundGroupSession::from(&outbound);

        assert!(session.connected(&mut clone));
        assert!(clone.connected(&mut session));

        clone.advance_to(10);

        assert!(session.connected(&mut clone));
        assert!(clone.connected(&mut session));

        let mut other = InboundGroupSession::from(&GroupSession::new(Default::default()));

        assert!(!session.connected(&mut other));
        assert!(!clone.connected(&mut other));

        other.signing_key = session.signing_key;

        assert!(!session.connected(&mut other));
        assert!(!clone.connected(&mut other));

        let session_key = session.export_at_first_known_index();
        let mut different_config =
            InboundGroupSession::import(&session_key, SessionConfig::version_1());

        assert!(!session.connected(&mut different_config));
        assert!(!different_config.connected(&mut session));
    }

    #[test]
    fn comparison() {
        let outbound = GroupSession::new(Default::default());
        let mut session = InboundGroupSession::from(&outbound);
        let mut clone = InboundGroupSession::from(&outbound);

        assert_eq!(session.compare(&mut clone), SessionOrdering::Equal);
        assert_eq!(clone.compare(&mut session), SessionOrdering::Equal);

        clone.advance_to(10);

        assert_eq!(session.compare(&mut clone), SessionOrdering::Better);
        assert_eq!(clone.compare(&mut session), SessionOrdering::Worse);

        let mut other = InboundGroupSession::from(&GroupSession::new(Default::default()));

        assert_eq!(session.compare(&mut other), SessionOrdering::Unconnected);
        assert_eq!(clone.compare(&mut other), SessionOrdering::Unconnected);

        other.signing_key = session.signing_key;

        assert_eq!(session.compare(&mut other), SessionOrdering::Unconnected);
        assert_eq!(clone.compare(&mut other), SessionOrdering::Unconnected);
    }

    #[test]
    fn upgrade() {
        let session = GroupSession::new(Default::default());
        let session_key = session.session_key();

        let mut first_session = InboundGroupSession::new(&session_key, Default::default());

        // This one is less trusted because it's imported from an `ExportedSessionKey`.
        let mut second_session =
            InboundGroupSession::import(&first_session.export_at(10).unwrap(), Default::default());
        assert!(!second_session.signing_key_verified);

        assert_eq!(first_session.compare(&mut second_session), SessionOrdering::Better);

        let mut merged = second_session.merge(&mut first_session).unwrap();

        assert!(merged.signing_key_verified);
        assert_eq!(merged.compare(&mut second_session), SessionOrdering::Better);
        assert_eq!(merged.compare(&mut first_session), SessionOrdering::Equal);
    }

    #[test]
    fn verify_mac() {
        let olm_session = OlmOutboundGroupSession::new();
        let session_key = SessionKey::from_base64(&olm_session.session_key()).unwrap();
        let message = olm_session.encrypt("Hello").as_str().try_into().unwrap();

        let mut session = InboundGroupSession::new(&session_key, SessionConfig::version_1());
        let ratchet = session.find_ratchet(0).unwrap();
        let cipher = Cipher::new_megolm(ratchet.as_bytes());

        session
            .verify_mac(&cipher, &message)
            .expect("Should verify MAC from matching outbound session");

        let olm_session = OlmOutboundGroupSession::new();
        let session_key = SessionKey::from_base64(&olm_session.session_key()).unwrap();

        let mut session = InboundGroupSession::new(&session_key, SessionConfig::version_1());
        let ratchet = session.find_ratchet(0).unwrap();
        let cipher = Cipher::new_megolm(ratchet.as_bytes());

        session
            .verify_mac(&cipher, &message)
            .expect_err("Should not verify MAC from different outbound session");
    }

    /// Test that [`InboundGroupSession::get_cipher_at`] correctly handles the
    /// correct range of message indices.`
    #[cfg(feature = "low-level-api")]
    #[test]
    fn get_cipher_at() {
        let mut group_session = GroupSession::new(Default::default());

        // Advance the ratchet a few times by calling `encrypt`.
        group_session.encrypt("test1");
        group_session.encrypt("test2");

        let session = InboundGroupSession::from(&group_session);

        // The inbound session will only be able to decrypt messages from
        // indices starting at 2 (as we advanced the ratchet twice before
        // creating the inbound session)
        assert!(session.get_cipher_at(0).is_none());
        assert!(session.get_cipher_at(1).is_none());
        assert!(session.get_cipher_at(2).is_some());
        assert!(session.get_cipher_at(1000).is_some());

        // Now check that we actually *do* advance the ratchet. We do this by
        // checking that the ratchet changes.
        assert_ne!(
            session.get_cipher_at(2).unwrap().encrypt(b""),
            session.get_cipher_at(3).unwrap().encrypt(b"")
        );
        assert_ne!(
            session.get_cipher_at(3).unwrap().encrypt(b""),
            session.get_cipher_at(1000).unwrap().encrypt(b"")
        );
    }
}
