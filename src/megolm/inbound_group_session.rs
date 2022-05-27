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

use std::io::Read;

use aes::cipher::block_padding::UnpadError;
use hmac::digest::MacError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    message::MegolmMessage,
    ratchet::Ratchet,
    session_keys::{ExportedSessionKey, SessionKey},
    GroupSession,
};
use crate::{
    cipher::Cipher,
    types::{Ed25519PublicKey, SignatureError},
    utilities::{base64_encode, pickle, unpickle},
    PickleError,
};

/// Error type for Megolm-based decryption failuers.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// The signature on the message was invalid.
    #[error("The signature on the message was invalid: {0}")]
    Signature(#[from] SignatureError),
    /// The message authentication code of the message was invalid.
    #[error("Failed decrypting Megolm message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),
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

#[derive(Deserialize)]
#[serde(try_from = "InboundGroupSessionPickle")]
pub struct InboundGroupSession {
    initial_ratchet: Ratchet,
    latest_ratchet: Ratchet,
    signing_key: Ed25519PublicKey,
    #[allow(dead_code)]
    signing_key_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

impl InboundGroupSession {
    pub fn new(key: &SessionKey) -> Self {
        let initial_ratchet =
            Ratchet::from_bytes(key.session_key.ratchet.clone(), key.session_key.ratchet_index);
        let latest_ratchet = initial_ratchet.clone();

        Self {
            initial_ratchet,
            latest_ratchet,
            signing_key: key.session_key.signing_key,
            signing_key_verified: true,
        }
    }

    pub fn import(session_key: &ExportedSessionKey) -> Self {
        let initial_ratchet =
            Ratchet::from_bytes(session_key.ratchet.clone(), session_key.ratchet_index);
        let latest_ratchet = initial_ratchet.clone();

        Self {
            initial_ratchet,
            latest_ratchet,
            signing_key: session_key.signing_key,
            signing_key_verified: false,
        }
    }

    pub fn session_id(&self) -> String {
        base64_encode(self.signing_key.as_bytes())
    }

    pub fn first_known_index(&self) -> u32 {
        self.initial_ratchet.index()
    }

    /// Permanently advance the session to the given index.
    ///
    /// This will remove the ability to decrypt messages that were encrypted
    /// with a lower message index than what is given as the argument.
    ///
    /// Returns true if the ratchet has been advanced, false if the ratchet was
    /// already advanced past the given index.
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

    pub fn decrypt(
        &mut self,
        message: &MegolmMessage,
    ) -> Result<DecryptedMessage, DecryptionError> {
        self.signing_key.verify(&message.to_signature_bytes(), &message.signature)?;

        if let Some(ratchet) = self.find_ratchet(message.message_index) {
            let cipher = Cipher::new_megolm(ratchet.as_bytes());

            cipher.verify_mac(&message.to_mac_bytes(), &message.mac)?;
            let plaintext =
                String::from_utf8_lossy(&cipher.decrypt(&message.ciphertext)?).to_string();

            Ok(DecryptedMessage { plaintext, message_index: message.message_index })
        } else {
            Err(DecryptionError::UnknownMessageIndex(
                self.initial_ratchet.index(),
                message.message_index,
            ))
        }
    }

    pub fn export_at(&mut self, index: u32) -> Option<ExportedSessionKey> {
        let signing_key = self.signing_key;

        self.find_ratchet(index).map(|ratchet| ExportedSessionKey::new(ratchet, signing_key))
    }

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
        }
    }

    /// Restore an [`InboundGroupSession`] from a previously saved
    /// [`InboundGroupSessionPickle`].
    pub fn from_pickle(pickle: InboundGroupSessionPickle) -> Self {
        Self::from(pickle)
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, crate::LibolmPickleError> {
        use super::libolm::LibolmRatchetPickle;
        use crate::utilities::{unpickle_libolm, Decode};

        #[derive(Zeroize)]
        #[zeroize(drop)]
        struct Pickle {
            version: u32,
            initial_ratchet: LibolmRatchetPickle,
            latest_ratchet: LibolmRatchetPickle,
            signing_key: [u8; 32],
            signing_key_verified: bool,
        }

        impl Decode for Pickle {
            fn decode(reader: &mut impl Read) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Pickle {
                    version: u32::decode(reader)?,
                    initial_ratchet: LibolmRatchetPickle::decode(reader)?,
                    latest_ratchet: LibolmRatchetPickle::decode(reader)?,
                    signing_key: <[u8; 32]>::decode(reader)?,
                    signing_key_verified: bool::decode(reader)?,
                })
            }
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

                Ok(Self { initial_ratchet, latest_ratchet, signing_key, signing_key_verified })
            }
        }

        const PICKLE_VERSION: u32 = 2;

        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
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
        }
    }
}

impl From<&GroupSession> for InboundGroupSession {
    fn from(session: &GroupSession) -> Self {
        Self::new(&session.session_key())
    }
}

#[cfg(test)]
mod test {
    use super::InboundGroupSession;
    use crate::megolm::GroupSession;

    #[test]
    fn advance_inbound_session() {
        let mut session = InboundGroupSession::from(&GroupSession::new());

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

    /// Test that [`InboundGroupSession::get_cipher_at`] correctly handles the
    /// correct range of message indices.`
    #[cfg(feature = "low-level-api")]
    #[test]
    fn get_cipher_at() {
        let mut group_session = GroupSession::new();

        // Advance the ratchet a few times by calling `encrypt`.
        group_session.encrypt("test1");
        group_session.encrypt("test2");

        let session = InboundGroupSession::from(&group_session);

        println!("{}", session.first_known_index());

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
