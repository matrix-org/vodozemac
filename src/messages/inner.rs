// Copyright 2021 Damir Jelić
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

use ed25519_dalek::SignatureError;
use prost::Message;
use thiserror::Error;

use crate::{cipher::Mac, utilities::VarInt, Curve25519KeyError, Curve25519PublicKey};

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("The message didn't contain a version")]
    MissingVersion,
    #[error("The message was too short, it didn't contain a valid payload")]
    MessageTooShort(usize),
    #[error("The message didn't have a valid version, expected {0}, got {1}")]
    InvalidVersion(u8, u8),
    #[error("The message contained an invalid public key: {0}")]
    InvalidKey(#[from] Curve25519KeyError),
    #[error("The message contained a MAC with an invalid size, expected {0}, got {1}")]
    InvalidMacLength(usize, usize),
    #[error("The message contained an invalid Signature: {0}")]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    ProtoBufError(#[from] prost::DecodeError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct OlmMessage {
    inner: Vec<u8>,
}

impl From<Vec<u8>> for OlmMessage {
    fn from(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }
}

impl OlmMessage {
    const VERSION: u8 = 3;

    const RATCHET_TAG: &'static [u8; 1] = b"\x0A";
    const INDEX_TAG: &'static [u8; 1] = b"\x10";
    const CIPHER_TAG: &'static [u8; 1] = b"\x22";

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }

    pub fn as_payload_bytes(&self) -> &[u8] {
        let end = self.inner.len();
        &self.inner[..end - 8]
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }

    pub(crate) fn append_mac(&mut self, mac: Mac) {
        let truncated = mac.truncate();
        self.append_mac_bytes(&truncated)
    }

    fn append_mac_bytes(&mut self, mac: &[u8; Mac::TRUNCATED_LEN]) {
        let end = self.inner.len();
        self.inner[end - Mac::TRUNCATED_LEN..].copy_from_slice(mac);
    }

    pub(crate) fn decode(&self) -> Result<DecodedMessage, DecodeError> {
        let version = *self.inner.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != Self::VERSION {
            Err(DecodeError::InvalidVersion(Self::VERSION, version))
        } else if self.inner.len() < Mac::TRUNCATED_LEN + 2 {
            Err(DecodeError::MessageTooShort(self.inner.len()))
        } else {
            let inner =
                InnerMessage::decode(&self.inner[1..self.inner.len() - Mac::TRUNCATED_LEN])?;

            let mac_slice = &self.inner[self.inner.len() - Mac::TRUNCATED_LEN..];

            if mac_slice.len() != Mac::TRUNCATED_LEN {
                Err(DecodeError::InvalidMacLength(Mac::TRUNCATED_LEN, mac_slice.len()))
            } else {
                let mut mac = [0u8; Mac::TRUNCATED_LEN];
                mac.copy_from_slice(mac_slice);

                let chain_index = inner.chain_index;
                let ciphertext = inner.ciphertext;
                let ratchet_key = Curve25519PublicKey::from_slice(&inner.ratchet_key)?;

                let message = DecodedMessage { ratchet_key, chain_index, ciphertext, mac };

                Ok(message)
            }
        }
    }

    fn from_parts_untyped(ratchet_key: &[u8], index: u64, ciphertext: Vec<u8>) -> Self {
        // Prost optimizes away the chain index if it's 0, libolm can't decode
        // this, so encode our messages the pedestrian way instead.
        let index = index.to_var_int();
        let ratchet_len = ratchet_key.len().to_var_int();
        let ciphertext_len = ciphertext.len().to_var_int();

        let message = [
            [Self::VERSION].as_ref(),
            Self::RATCHET_TAG.as_ref(),
            &ratchet_len,
            ratchet_key,
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &ciphertext,
            &[0u8; Mac::TRUNCATED_LEN],
        ]
        .concat();

        Self { inner: message }
    }

    pub fn from_parts(ratchet_key: &Curve25519PublicKey, index: u64, ciphertext: Vec<u8>) -> Self {
        Self::from_parts_untyped(ratchet_key.as_bytes(), index, ciphertext)
    }
}

#[derive(Clone, Debug)]
pub struct PreKeyMessage {
    pub(super) inner: Vec<u8>,
}

impl PreKeyMessage {
    const VERSION: u8 = 3;

    pub fn decode(
        self,
    ) -> Result<(Curve25519PublicKey, Curve25519PublicKey, Curve25519PublicKey, Vec<u8>), DecodeError>
    {
        let version = *self.inner.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != Self::VERSION {
            Err(DecodeError::InvalidVersion(Self::VERSION, version))
        } else {
            let inner = InnerPreKeyMessage::decode(&self.inner[1..self.inner.len()])?;

            let one_time_key = Curve25519PublicKey::from_slice(&inner.one_time_key)?;
            let base_key = Curve25519PublicKey::from_slice(&inner.base_key)?;
            let identity_key = Curve25519PublicKey::from_slice(&inner.identity_key)?;

            Ok((one_time_key, base_key, identity_key, inner.message))
        }
    }

    pub fn from_parts(
        one_time_key: &Curve25519PublicKey,
        base_key: &Curve25519PublicKey,
        identity_key: &Curve25519PublicKey,
        message: Vec<u8>,
    ) -> Self {
        Self::from_parts_untyped_prost(
            one_time_key.as_bytes().to_vec(),
            base_key.as_bytes().to_vec(),
            identity_key.as_bytes().to_vec(),
            message,
        )
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }

    fn from_parts_untyped_prost(
        one_time_key: Vec<u8>,
        base_key: Vec<u8>,
        identity_key: Vec<u8>,
        message: Vec<u8>,
    ) -> Self {
        let message = InnerPreKeyMessage { one_time_key, base_key, identity_key, message };

        let mut output: Vec<u8> = vec![0u8; message.encoded_len() + 1];
        output[0] = Self::VERSION;

        message
            .encode(&mut output[1..].as_mut())
            .expect("Couldn't encode our message into a protobuf");

        Self { inner: output }
    }
}

impl From<Vec<u8>> for PreKeyMessage {
    fn from(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }
}

pub(crate) struct DecodedMessage {
    pub ratchet_key: Curve25519PublicKey,
    pub chain_index: u64,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 8],
}

#[derive(Clone, Message, PartialEq)]
struct InnerMessage {
    #[prost(bytes, tag = "1")]
    pub ratchet_key: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub chain_index: u64,
    #[prost(bytes, tag = "4")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Message)]
struct InnerPreKeyMessage {
    #[prost(bytes, tag = "1")]
    pub one_time_key: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub base_key: Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub identity_key: Vec<u8>,
    #[prost(bytes, tag = "4")]
    pub message: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::OlmMessage;

    #[test]
    fn encode() {
        let message = b"\x03\n\nratchetkey\x10\x01\"\nciphertext";
        let message_mac = b"\x03\n\nratchetkey\x10\x01\"\nciphertextMACHEREE";

        let ratchet_key = b"ratchetkey";
        let ciphertext = b"ciphertext";

        let mut encoded = OlmMessage::from_parts_untyped(ratchet_key, 1, ciphertext.to_vec());

        assert_eq!(encoded.as_payload_bytes(), message.as_ref());
        encoded.append_mac_bytes(b"MACHEREE");
        assert_eq!(encoded.as_payload_bytes(), message.as_ref());
        assert_eq!(encoded.as_bytes(), message_mac.as_ref());
    }
}
