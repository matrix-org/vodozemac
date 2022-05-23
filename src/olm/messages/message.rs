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
use serde::{Deserialize, Serialize};

use crate::{
    cipher::Mac,
    utilities::{base64_decode, base64_encode, VarInt},
    Curve25519PublicKey, DecodeError,
};

const VERSION: u8 = 3;

/// An encrypted Olm message.
///
/// Contains metadata that is required to find the correct ratchet state of a
/// [`Session`] necessary to decrypt the message.
///
/// [`Session`]: crate::olm::Session
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub(crate) ratchet_key: Curve25519PublicKey,
    pub(crate) chain_index: u64,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) mac: [u8; Mac::TRUNCATED_LEN],
}

impl Message {
    /// The public part of the ratchet key, that was used when the message was
    /// encrypted.
    pub fn ratchet_key(&self) -> Curve25519PublicKey {
        self.ratchet_key
    }

    /// The index of the chain that was used when the message was encrypted.
    pub fn chain_index(&self) -> u64 {
        self.chain_index
    }

    /// The actual ciphertext of the message.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Try to decode the given byte slice as a Olm [`Message`].
    ///
    /// The expected format of the byte array is described in the
    /// [`Message::to_bytes()`] method.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(bytes)
    }

    /// Encode the `Message` as an array of bytes.
    ///
    /// Olm `Message`s consist of a one-byte version, followed by a variable
    /// length payload and a fixed length message authentication code.
    ///
    /// ```text
    /// +--------------+------------------------------------+-----------+
    /// | Version Byte | Payload Bytes                      | MAC Bytes |
    /// +--------------+------------------------------------+-----------+
    /// ```
    ///
    /// The payload uses a format based on the Protocol Buffers encoding. It
    /// consists of the following key-value pairs:
    ///
    /// **Name**   |**Tag**|**Type**|               **Meaning**
    /// :---------:|:-----:|:------:|:-----------------------------------------:
    /// Ratchet-Key|  0x0A | String |The public part of the ratchet key
    /// Chain-Index|  0x10 | Integer|The chain index, of the message
    /// Cipher-Text|  0x22 | String |The cipher-text of the message
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut message = self.encode();
        message.extend(self.mac);

        message
    }

    /// Try to decode the given string as a Olm [`Message`].
    ///
    /// The string needs to be a base64 encoded byte array that follows the
    /// format described in the [`Message::to_bytes()`] method.
    pub fn from_base64(message: &str) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    /// Encode the [`Message`] as a string.
    ///
    /// This method first calls [`Message::to_bytes()`] and then encodes the
    /// resulting byte array as a string using base64 encoding.
    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    pub(crate) fn new(
        ratchet_key: Curve25519PublicKey,
        chain_index: u64,
        ciphertext: Vec<u8>,
    ) -> Self {
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
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let message = self.to_base64();
        serializer.serialize_str(&message)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ciphertext = String::deserialize(d)?;
        Message::from_base64(&ciphertext).map_err(serde::de::Error::custom)
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
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
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

#[derive(ProstMessage, PartialEq, Eq)]
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
