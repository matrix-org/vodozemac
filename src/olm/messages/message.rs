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

use prost::Message as ProstMessage;

use crate::{
    cipher::Mac,
    utilities::{base64_decode, base64_encode, VarInt},
    Curve25519PublicKey, DecodeError,
};

const VERSION: u8 = 3;

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub ratchet_key: Curve25519PublicKey,
    pub chain_index: u64,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; Mac::TRUNCATED_LEN],
}

impl Message {
    pub fn new(ratchet_key: Curve25519PublicKey, chain_index: u64, ciphertext: Vec<u8>) -> Self {
        Self { ratchet_key, chain_index, ciphertext, mac: [0u8; Mac::TRUNCATED_LEN] }
    }

    fn encode(&self) -> Vec<u8> {
        ProtoBufMessage {
            ratchet_key: self.ratchet_key.to_bytes().to_vec(),
            chain_index: self.chain_index,
            ciphertext: self.ciphertext.clone(),
        }
        .encode_manual()
    }

    pub(crate) fn to_mac_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, DecodeError> {
        Self::try_from(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut message = self.encode();
        message.extend(self.mac);

        message
    }

    pub fn from_base64(message: &str) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }
}

impl TryFrom<&str> for Message {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let decoded = base64_decode(value)?;

        Self::try_from(decoded)
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let version = *value.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != VERSION {
            Err(DecodeError::InvalidVersion(VERSION, version))
        } else if value.len() < Mac::TRUNCATED_LEN + 2 {
            Err(DecodeError::MessageTooShort(value.len()))
        } else {
            let inner = ProtoBufMessage::decode(&value[1..value.len() - Mac::TRUNCATED_LEN])?;

            let mac_slice = &value[value.len() - Mac::TRUNCATED_LEN..];

            if mac_slice.len() != Mac::TRUNCATED_LEN {
                Err(DecodeError::InvalidMacLength(Mac::TRUNCATED_LEN, mac_slice.len()))
            } else {
                let mut mac = [0u8; Mac::TRUNCATED_LEN];
                mac.copy_from_slice(mac_slice);

                let chain_index = inner.chain_index;
                let ciphertext = inner.ciphertext;
                let ratchet_key = Curve25519PublicKey::from_slice(&inner.ratchet_key)?;

                let message = Message { ratchet_key, chain_index, ciphertext, mac };

                Ok(message)
            }
        }
    }
}

#[derive(ProstMessage, PartialEq)]
struct ProtoBufMessage {
    #[prost(bytes, tag = "1")]
    ratchet_key: Vec<u8>,
    #[prost(uint64, tag = "2")]
    chain_index: u64,
    #[prost(bytes, tag = "4")]
    ciphertext: Vec<u8>,
}

impl ProtoBufMessage {
    const RATCHET_TAG: &'static [u8; 1] = b"\x0A";
    const INDEX_TAG: &'static [u8; 1] = b"\x10";
    const CIPHER_TAG: &'static [u8; 1] = b"\x22";

    fn encode_manual(&self) -> Vec<u8> {
        let index = self.chain_index.to_var_int();
        let ratchet_len = self.ratchet_key.len().to_var_int();
        let ciphertext_len = self.ciphertext.len().to_var_int();

        [
            [VERSION].as_ref(),
            Self::RATCHET_TAG.as_ref(),
            &ratchet_len,
            &self.ratchet_key,
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &self.ciphertext,
        ]
        .concat()
    }
}

#[cfg(test)]
mod test {
    use super::Message;
    use crate::Curve25519PublicKey;

    #[test]
    fn encode() {
        let message = b"\x03\n\x20ratchetkeyhereprettyplease123456\x10\x01\"\nciphertext";
        let message_mac =
            b"\x03\n\x20ratchetkeyhereprettyplease123456\x10\x01\"\nciphertextMACHEREE";

        let ratchet_key = Curve25519PublicKey::from(*b"ratchetkeyhereprettyplease123456");
        let ciphertext = b"ciphertext";

        let mut encoded = Message::new(ratchet_key, 1, ciphertext.to_vec());
        encoded.mac = *b"MACHEREE";

        assert_eq!(encoded.to_mac_bytes(), message.as_ref());
        assert_eq!(encoded.to_bytes(), message_mac.as_ref());
    }
}
