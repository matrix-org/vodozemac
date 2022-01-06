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

use prost::Message;

use crate::{
    cipher::Mac,
    utilities::{base64_decode, VarInt},
    Curve25519PublicKey, DecodeError,
};

pub(crate) struct OlmMessage {
    pub source: EncodedOlmMessage,
    pub ratchet_key: Curve25519PublicKey,
    pub chain_index: u64,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 8],
}

impl TryFrom<&str> for OlmMessage {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let decoded = base64_decode(value)?;

        Self::try_from(decoded)
    }
}

impl TryFrom<Vec<u8>> for OlmMessage {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let version = *value.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != EncodedOlmMessage::VERSION {
            Err(DecodeError::InvalidVersion(EncodedOlmMessage::VERSION, version))
        } else if value.len() < Mac::TRUNCATED_LEN + 2 {
            Err(DecodeError::MessageTooShort(value.len()))
        } else {
            let inner = InnerMessage::decode(&value[1..value.len() - Mac::TRUNCATED_LEN])?;

            let mac_slice = &value[value.len() - Mac::TRUNCATED_LEN..];

            if mac_slice.len() != Mac::TRUNCATED_LEN {
                Err(DecodeError::InvalidMacLength(Mac::TRUNCATED_LEN, mac_slice.len()))
            } else {
                let mut mac = [0u8; Mac::TRUNCATED_LEN];
                mac.copy_from_slice(mac_slice);

                let chain_index = inner.chain_index;
                let ciphertext = inner.ciphertext;
                let ratchet_key = Curve25519PublicKey::from_slice(&inner.ratchet_key)?;

                let message = OlmMessage {
                    source: EncodedOlmMessage(value),
                    ratchet_key,
                    chain_index,
                    ciphertext,
                    mac,
                };

                Ok(message)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedOlmMessage(Vec<u8>);

impl EncodedOlmMessage {
    const VERSION: u8 = 3;

    const RATCHET_TAG: &'static [u8; 1] = b"\x0A";
    const INDEX_TAG: &'static [u8; 1] = b"\x10";
    const CIPHER_TAG: &'static [u8; 1] = b"\x22";

    pub fn new(ratchet_key: &Curve25519PublicKey, index: u64, ciphertext: Vec<u8>) -> Self {
        Self::from_parts_untyped(ratchet_key.as_bytes(), index, ciphertext)
    }

    pub fn as_payload_bytes(&self) -> &[u8] {
        let end = self.0.len();
        &self.0[..end - 8]
    }

    pub(crate) fn append_mac(&mut self, mac: Mac) {
        let truncated = mac.truncate();
        self.append_mac_bytes(&truncated)
    }

    fn append_mac_bytes(&mut self, mac: &[u8; Mac::TRUNCATED_LEN]) {
        let end = self.0.len();
        self.0[end - Mac::TRUNCATED_LEN..].copy_from_slice(mac);
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

        Self(message)
    }
}

impl AsRef<[u8]> for EncodedOlmMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) struct PreKeyMessage {
    pub public_one_time_key: Curve25519PublicKey,
    pub remote_one_time_key: Curve25519PublicKey,
    pub remote_identity_key: Curve25519PublicKey,
    pub message: OlmMessage,
}

impl TryFrom<&str> for PreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let decoded = base64_decode(value)?;

        Self::try_from(decoded)
    }
}

impl TryFrom<Vec<u8>> for PreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let version = *value.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != EncodedPrekeyMessage::VERSION {
            Err(DecodeError::InvalidVersion(EncodedPrekeyMessage::VERSION, version))
        } else {
            let decoded = InnerPreKeyMessage::decode(&value[1..value.len()])?;
            let one_time_key = Curve25519PublicKey::from_slice(&decoded.one_time_key)?;
            let base_key = Curve25519PublicKey::from_slice(&decoded.base_key)?;
            let identity_key = Curve25519PublicKey::from_slice(&decoded.identity_key)?;

            let message = decoded.message.try_into()?;

            Ok(Self {
                public_one_time_key: one_time_key,
                remote_one_time_key: base_key,
                remote_identity_key: identity_key,
                message,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedPrekeyMessage {
    pub(super) inner: Vec<u8>,
}

impl EncodedPrekeyMessage {
    const VERSION: u8 = 3;

    pub fn new(
        one_time_key: &Curve25519PublicKey,
        base_key: &Curve25519PublicKey,
        identity_key: &Curve25519PublicKey,
        message: EncodedOlmMessage,
    ) -> Self {
        let message = InnerPreKeyMessage {
            one_time_key: one_time_key.as_bytes().to_vec(),
            base_key: base_key.as_bytes().to_vec(),
            identity_key: identity_key.as_bytes().to_vec(),
            message: message.0,
        };

        let mut output: Vec<u8> = vec![0u8; message.encoded_len() + 1];
        output[0] = Self::VERSION;

        message
            .encode(&mut output[1..].as_mut())
            .expect("Couldn't encode our message into a protobuf");

        Self { inner: output }
    }
}

impl From<Vec<u8>> for EncodedPrekeyMessage {
    fn from(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }
}

impl AsRef<[u8]> for EncodedPrekeyMessage {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
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
    use super::EncodedOlmMessage;

    #[test]
    fn encode() {
        let message = b"\x03\n\nratchetkey\x10\x01\"\nciphertext";
        let message_mac = b"\x03\n\nratchetkey\x10\x01\"\nciphertextMACHEREE";

        let ratchet_key = b"ratchetkey";
        let ciphertext = b"ciphertext";

        let mut encoded =
            EncodedOlmMessage::from_parts_untyped(ratchet_key, 1, ciphertext.to_vec());

        assert_eq!(encoded.as_payload_bytes(), message.as_ref());
        encoded.append_mac_bytes(b"MACHEREE");
        assert_eq!(encoded.as_payload_bytes(), message.as_ref());
        assert_eq!(encoded.as_ref(), message_mac.as_ref());
    }
}
