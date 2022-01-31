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

use std::{
    io::{Cursor, Read},
    ops::Deref,
};

use block_modes::BlockModeError;
use hmac::digest::MacError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    message::MegolmMessage,
    ratchet::{MegolmRatchetUnpicklingError, Ratchet, RatchetPickle},
    GroupSession, SessionKey, SESSION_KEY_VERSION,
};
use crate::{
    cipher::Cipher,
    types::{Ed25519PublicKey, Ed25519Signature, SignatureError},
    utilities::{base64_decode, base64_encode},
    DecodeError,
};

const SESSION_KEY_EXPORT_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum SessionCreationError {
    #[error("The session had a invalid version, expected {0}, got {1}")]
    Version(u8, u8),
    #[error("The session key was too short {0}")]
    Read(#[from] std::io::Error),
    #[error("The session key wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("The signature on the session key was invalid: {0}")]
    Signature(#[from] SignatureError),
    #[error("The public key of session was invalid: {0}")]
    PublicKey(#[from] crate::PublicKeyError),
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("The signature on the session key was invalid: {0}")]
    Signature(#[from] SignatureError),
    #[error("Failed decrypting Megolm message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),
    #[error("Failed decrypting Megolm message, invalid ciphertext: {0}")]
    InvalidCiphertext(#[from] BlockModeError),
    #[error(
        "The message was encrypted using an unknown message index, \
        first known index {0}, index of the message {1}"
    )]
    UnknownMessageIndex(u32, u32),
    #[error("The message couldn't be decoded: {0}")]
    DecodeError(#[from] DecodeError),
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

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

#[derive(Zeroize, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExportedSessionKey(pub String);

impl ExportedSessionKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ExportedSessionKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl InboundGroupSession {
    pub fn new(session_key: &SessionKey) -> Result<Self, SessionCreationError> {
        Self::new_helper(&session_key.0, false)
    }

    pub fn import(exported_session_key: &ExportedSessionKey) -> Result<Self, SessionCreationError> {
        Self::new_helper(&exported_session_key.0, true)
    }

    fn new_helper(session_key: &str, is_export: bool) -> Result<Self, SessionCreationError> {
        let decoded = base64_decode(session_key)?;
        let mut cursor = Cursor::new(decoded);

        let mut version = [0u8; 1];
        let mut index = [0u8; 4];
        let mut ratchet = [0u8; 128];
        let mut public_key = [0u8; Ed25519PublicKey::LENGTH];

        cursor.read_exact(&mut version)?;

        let expected_version =
            if is_export { SESSION_KEY_EXPORT_VERSION } else { SESSION_KEY_VERSION };

        if version[0] != expected_version {
            Err(SessionCreationError::Version(SESSION_KEY_VERSION, version[0]))
        } else {
            cursor.read_exact(&mut index)?;
            cursor.read_exact(&mut ratchet)?;
            cursor.read_exact(&mut public_key)?;

            let signing_key = Ed25519PublicKey::from_slice(&public_key)?;

            let signing_key_verified = if !is_export {
                let mut signature = [0u8; Ed25519Signature::LENGTH];

                cursor.read_exact(&mut signature)?;
                let signature = Ed25519Signature::from_slice(&signature)?;

                let decoded = cursor.into_inner();

                signing_key.verify(&decoded[..decoded.len() - 64], &signature)?;

                true
            } else {
                false
            };

            let index = u32::from_be_bytes(index);
            let initial_ratchet = Ratchet::from_bytes(ratchet, index);
            let latest_ratchet = initial_ratchet.clone();

            Ok(Self { initial_ratchet, latest_ratchet, signing_key, signing_key_verified })
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

    pub fn decrypt(&mut self, ciphertext: &str) -> Result<DecryptedMessage, DecryptionError> {
        let message = MegolmMessage::try_from(ciphertext)?;

        self.signing_key.verify(message.source.bytes_for_signing(), &message.signature)?;

        if let Some(ratchet) = self.find_ratchet(message.message_index) {
            let cipher = Cipher::new_megolm(ratchet.as_bytes());

            cipher.verify_mac(message.source.bytes_for_mac(), &message.mac)?;
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

        if let Some(ratchet) = self.find_ratchet(index) {
            let index = ratchet.index().to_be_bytes();

            let mut export: Vec<u8> = [
                [SESSION_KEY_EXPORT_VERSION].as_ref(),
                index.as_ref(),
                ratchet.as_bytes(),
                signing_key.as_bytes(),
            ]
            .concat();

            let result = base64_encode(&export);
            export.zeroize();

            Some(ExportedSessionKey(result))
        } else {
            None
        }
    }

    pub fn pickle_to_json_string(&self) -> InboundGroupSessionPickledJSON {
        let pickle: InboundGroupSessionPickle = self.pickle();
        InboundGroupSessionPickledJSON(
            serde_json::to_string_pretty(&pickle)
                .expect("Inbound group session serialization failed."),
        )
    }

    pub fn unpickle_from_json_str(input: &str) -> Result<Self, InboundGroupSessionUnpicklingError> {
        let pickle: InboundGroupSessionPickle = serde_json::from_str(input)?;
        pickle.try_into()
    }

    pub fn pickle(&self) -> InboundGroupSessionPickle {
        InboundGroupSessionPickle {
            initial_ratchet: self.initial_ratchet.clone().into(),
            latest_ratchet: self.latest_ratchet.clone().into(),
            signing_key: self.signing_key,
            signing_key_verified: self.signing_key_verified,
        }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &str,
    ) -> Result<Self, crate::LibolmUnpickleError> {
        use crate::utilities::{unpickle_libolm, Decode};

        #[derive(Zeroize)]
        #[zeroize(drop)]
        struct RatchetPickle {
            ratchet: [u8; 128],
            index: u32,
        }

        impl From<&RatchetPickle> for Ratchet {
            fn from(pickle: &RatchetPickle) -> Self {
                Ratchet::from_bytes(pickle.ratchet, pickle.index)
            }
        }

        impl Decode for RatchetPickle {
            fn decode(reader: &mut impl Read) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(RatchetPickle {
                    ratchet: <[u8; 128]>::decode(reader)?,
                    index: u32::decode(reader)?,
                })
            }
        }

        #[derive(Zeroize)]
        #[zeroize(drop)]
        struct Pickle {
            version: u32,
            initial_ratchet: RatchetPickle,
            latest_ratchet: RatchetPickle,
            signing_key: [u8; 32],
            signing_key_verified: bool,
        }

        impl Decode for Pickle {
            fn decode(reader: &mut impl Read) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Pickle {
                    version: u32::decode(reader)?,
                    initial_ratchet: RatchetPickle::decode(reader)?,
                    latest_ratchet: RatchetPickle::decode(reader)?,
                    signing_key: <[u8; 32]>::decode(reader)?,
                    signing_key_verified: bool::decode(reader)?,
                })
            }
        }

        impl TryFrom<Pickle> for InboundGroupSession {
            type Error = crate::LibolmUnpickleError;

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

#[derive(Serialize, Deserialize)]
pub struct InboundGroupSessionPickle {
    initial_ratchet: RatchetPickle,
    latest_ratchet: RatchetPickle,
    signing_key: Ed25519PublicKey,
    #[allow(dead_code)]
    signing_key_verified: bool,
}

impl InboundGroupSessionPickle {
    pub fn unpickle(self) -> Result<InboundGroupSession, InboundGroupSessionUnpicklingError> {
        self.try_into()
    }
}

impl TryFrom<InboundGroupSessionPickle> for InboundGroupSession {
    type Error = InboundGroupSessionUnpicklingError;

    fn try_from(pickle: InboundGroupSessionPickle) -> Result<Self, Self::Error> {
        Ok(Self {
            initial_ratchet: pickle
                .initial_ratchet
                .try_into()
                .map_err(InboundGroupSessionUnpicklingError::InvalidInitialRatchet)?,
            latest_ratchet: pickle
                .latest_ratchet
                .try_into()
                .map_err(InboundGroupSessionUnpicklingError::InvalidLatestRatchet)?,
            signing_key: pickle.signing_key,
            signing_key_verified: pickle.signing_key_verified,
        })
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct InboundGroupSessionPickledJSON(String);

impl InboundGroupSessionPickledJSON {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn unpickle(self) -> Result<InboundGroupSession, InboundGroupSessionUnpicklingError> {
        let pickle: InboundGroupSessionPickle = serde_json::from_str(&self.0)?;
        pickle.unpickle()
    }
}

impl AsRef<str> for InboundGroupSessionPickledJSON {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for InboundGroupSessionPickledJSON {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl From<&GroupSession> for InboundGroupSession {
    fn from(session: &GroupSession) -> Self {
        Self::new(&session.session_key()).expect("Can't import the session key export")
    }
}

#[derive(Error, Debug)]
pub enum InboundGroupSessionUnpicklingError {
    #[error("Invalid initial ratchet")]
    InvalidInitialRatchet(MegolmRatchetUnpicklingError),
    #[error("Invalid latest ratchet")]
    InvalidLatestRatchet(MegolmRatchetUnpicklingError),
    #[error("Invalid public signing key: {0}")]
    InvalidSigningPublicKey(SignatureError),
    #[error("Pickle format corrupted: {0}")]
    CorruptedPickle(#[from] serde_json::error::Error),
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
}
