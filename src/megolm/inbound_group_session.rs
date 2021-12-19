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

use std::io::{Cursor, Read};

use block_modes::BlockModeError;
use ed25519_dalek::{
    PublicKey, Signature, SignatureError, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use hmac::digest::MacError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    group_session::PublicKeyPickle,
    message::MegolmMessage,
    ratchet::{MegolmRatchetUnpicklingError, Ratchet, RatchetPickle},
    SessionKey, SESSION_KEY_VERSION,
};
use crate::{
    cipher::Cipher,
    messages::DecodeError,
    utilities::{base64_decode, base64_encode},
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
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("The message wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
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
    signing_key: PublicKey,
    #[allow(dead_code)]
    signing_key_verified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

#[derive(Zeroize)]
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
        let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

        cursor.read_exact(&mut version)?;

        let expected_version =
            if is_export { SESSION_KEY_EXPORT_VERSION } else { SESSION_KEY_VERSION };

        if version[0] != expected_version {
            Err(SessionCreationError::Version(SESSION_KEY_VERSION, version[0]))
        } else {
            cursor.read_exact(&mut index)?;
            cursor.read_exact(&mut ratchet)?;
            cursor.read_exact(&mut public_key)?;

            let signing_key = PublicKey::from_bytes(&public_key)?;

            let signing_key_verified = if !is_export {
                let mut signature = [0u8; SIGNATURE_LENGTH];

                cursor.read_exact(&mut signature)?;
                let signature = Signature::from_bytes(&signature)?;

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
        let decoded = base64_decode(ciphertext)?;
        let (message, decoded) = MegolmMessage::decode(decoded)?;

        self.signing_key.verify(message.bytes_for_signing(), &decoded.signature)?;

        if let Some(ratchet) = self.find_ratchet(decoded.message_index) {
            let cipher = Cipher::new_megolm(ratchet.as_bytes());

            cipher.verify_mac(message.bytes_for_mac(), &decoded.mac)?;
            let plaintext =
                String::from_utf8_lossy(&cipher.decrypt(&decoded.ciphertext)?).to_string();

            Ok(DecryptedMessage { plaintext, message_index: decoded.message_index })
        } else {
            Err(DecryptionError::UnknownMessageIndex(
                self.initial_ratchet.index(),
                decoded.message_index,
            ))
        }
    }

    pub fn export_at(&mut self, index: u32) -> Option<ExportedSessionKey> {
        let signing_key = self.signing_key;

        if let Some(ratchet) = self.find_ratchet(index) {
            let index = ratchet.index().to_le_bytes();

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

    pub fn pickle(&self) -> InboundGroupSessionPickled {
        let pickle: InboundGroupSessionPickle = self.to_pickle();
        InboundGroupSessionPickled(
            serde_json::to_string_pretty(&pickle)
                .expect("Inbound group session serialization failed."),
        )
    }

    pub fn to_pickle(&self) -> InboundGroupSessionPickle {
        InboundGroupSessionPickle {
            initial_ratchet: self.initial_ratchet.clone().into(),
            latest_ratchet: self.latest_ratchet.clone().into(),
            signing_key: self.signing_key.into(),
            signing_key_verified: self.signing_key_verified,
        }
    }

    pub fn unpickle(input: &str) -> Result<Self, InboundGroupSessionUnpicklingError> {
        let pickle: InboundGroupSessionPickle = serde_json::from_str(input)?;
        pickle.try_into()
    }

    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &str,
    ) -> Result<Self, crate::LibolmUnpickleError> {
        use crate::utilities::{read_bool, read_u32};

        const PICKLE_VERSION: u32 = 2;

        let cipher = Cipher::new_pickle(pickle_key.as_ref());

        let decoded = base64_decode(pickle)?;
        let decrypted = cipher.decrypt_pickle(&decoded)?;

        let mut cursor = Cursor::new(decrypted);
        let version = read_u32(&mut cursor)?;

        if version != 2 {
            Err(crate::LibolmUnpickleError::Version(PICKLE_VERSION, version))
        } else {
            let mut ratchet = [0u8; Ratchet::RATCHET_LENGTH];

            cursor.read_exact(&mut ratchet)?;
            let counter = read_u32(&mut cursor)?;
            let initial_ratchet = Ratchet::from_bytes(ratchet, counter);

            cursor.read_exact(&mut ratchet)?;
            let counter = read_u32(&mut cursor)?;
            let latest_ratchet = Ratchet::from_bytes(ratchet, counter);

            let mut signing_key = [0u8; PUBLIC_KEY_LENGTH];
            cursor.read_exact(&mut signing_key)?;
            let signing_key = PublicKey::from_bytes(&signing_key)?;

            let signing_key_verified = read_bool(&mut cursor)?;

            Ok(Self { initial_ratchet, latest_ratchet, signing_key, signing_key_verified })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct InboundGroupSessionPickle {
    initial_ratchet: RatchetPickle,
    latest_ratchet: RatchetPickle,
    signing_key: PublicKeyPickle,
    #[allow(dead_code)]
    signing_key_verified: bool,
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
            signing_key: pickle
                .signing_key
                .try_into()
                .map_err(InboundGroupSessionUnpicklingError::InvalidSigningPublicKey)?,
            signing_key_verified: pickle.signing_key_verified,
        })
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct InboundGroupSessionPickled(String);

impl InboundGroupSessionPickled {
    pub fn as_str(&self) -> &str {
        &self.0
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
