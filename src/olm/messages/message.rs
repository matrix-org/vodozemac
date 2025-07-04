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

use std::fmt::Debug;

use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};

use crate::{
    Curve25519PublicKey, DecodeError,
    cipher::{Mac, MessageMac},
    utilities::{VarInt, base64_decode, base64_encode, extract_mac},
};

const MAC_TRUNCATED_VERSION: u8 = 3;
const VERSION: u8 = 4;

/// An encrypted Olm message.
///
/// Contains metadata that is required to find the correct ratchet state of a
/// [`Session`] necessary to decrypt the message.
///
/// [`Session`]: crate::olm::Session
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    pub(crate) version: u8,
    pub(crate) ratchet_key: Curve25519PublicKey,
    pub(crate) chain_index: u64,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) mac: MessageMac,
}

impl Message {
    /// The public part of the ratchet key, that was used when the message was
    /// encrypted.
    pub const fn ratchet_key(&self) -> Curve25519PublicKey {
        self.ratchet_key
    }

    /// The index of the chain that was used when the message was encrypted.
    pub const fn chain_index(&self) -> u64 {
        self.chain_index
    }

    /// The actual ciphertext of the message.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The version of the Olm message.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Has the MAC been truncated in this Olm message.
    pub const fn mac_truncated(&self) -> bool {
        self.version == MAC_TRUNCATED_VERSION
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
        message.extend(self.mac.as_bytes());

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
        Self {
            version: VERSION,
            ratchet_key,
            chain_index,
            ciphertext,
            mac: Mac([0u8; Mac::LENGTH]).into(),
        }
    }

    pub(crate) fn new_truncated_mac(
        ratchet_key: Curve25519PublicKey,
        chain_index: u64,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            version: MAC_TRUNCATED_VERSION,
            ratchet_key,
            chain_index,
            ciphertext,
            mac: [0u8; Mac::TRUNCATED_LEN].into(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        ProtoBufMessage {
            ratchet_key: self.ratchet_key.to_bytes().to_vec(),
            chain_index: self.chain_index,
            ciphertext: self.ciphertext.clone(),
        }
        .encode_manual(self.version)
    }

    pub(crate) fn to_mac_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    pub(crate) fn set_mac(&mut self, mac: Mac) {
        match self.mac {
            MessageMac::Truncated(_) => self.mac = mac.truncate().into(),
            MessageMac::Full(_) => self.mac = mac.into(),
        }
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
        let version = *value.first().ok_or(DecodeError::MissingVersion)?;

        let mac_length = match version {
            VERSION => Mac::LENGTH,
            MAC_TRUNCATED_VERSION => Mac::TRUNCATED_LEN,
            _ => return Err(DecodeError::InvalidVersion(VERSION, version)),
        };

        if value.len() < mac_length + 2 {
            Err(DecodeError::MessageTooShort(value.len()))
        } else {
            let inner = ProtoBufMessage::decode(
                value
                    .get(1..value.len() - mac_length)
                    .ok_or_else(|| DecodeError::MessageTooShort(value.len()))?,
            )?;

            let mac_slice = &value[value.len() - mac_length..];

            if mac_slice.len() != mac_length {
                Err(DecodeError::InvalidMacLength(mac_length, mac_slice.len()))
            } else {
                let mac = extract_mac(mac_slice, version == MAC_TRUNCATED_VERSION);

                let chain_index = inner.chain_index;
                let ciphertext = inner.ciphertext;
                let ratchet_key = Curve25519PublicKey::from_slice(&inner.ratchet_key)?;

                let message = Message { version, ratchet_key, chain_index, ciphertext, mac };

                Ok(message)
            }
        }
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { version, ratchet_key, chain_index, ciphertext: _, mac: _ } = self;

        f.debug_struct("Message")
            .field("version", version)
            .field("ratchet_key", ratchet_key)
            .field("chain_index", chain_index)
            .finish_non_exhaustive()
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

    fn encode_manual(&self, version: u8) -> Vec<u8> {
        let index = self.chain_index.to_var_int();
        let ratchet_len = self.ratchet_key.len().to_var_int();
        let ciphertext_len = self.ciphertext.len().to_var_int();

        [
            [version].as_ref(),
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
    use assert_matches2::{assert_let, assert_matches};

    use super::Message;
    use crate::{
        Curve25519PublicKey, DecodeError,
        olm::messages::message::{MAC_TRUNCATED_VERSION, VERSION},
    };

    #[test]
    fn encode() {
        let message = b"\x03\n\x20ratchetkeyhereprettyplease123456\x10\x02\"\nciphertext";
        let message_mac =
            b"\x03\n\x20ratchetkeyhereprettyplease123456\x10\x02\"\nciphertextMACHEREE";

        let ratchet_key = Curve25519PublicKey::from(*b"ratchetkeyhereprettyplease123456");
        let ciphertext = b"ciphertext";
        let chain_index = 2;

        let mut encoded = Message::new_truncated_mac(ratchet_key, chain_index, ciphertext.to_vec());
        encoded.mac = (*b"MACHEREE").into();

        assert_eq!(encoded.to_mac_bytes(), message.as_ref());
        assert_eq!(encoded.to_bytes(), message_mac.as_ref());
        assert_eq!(encoded.ciphertext(), ciphertext.to_vec());
        assert_eq!(encoded.chain_index(), chain_index);
        assert_eq!(encoded.version(), MAC_TRUNCATED_VERSION);
    }

    #[test]
    fn from_bytes_normal_message() {
        let bytes = b"\x04\n\x20ratchetkeyhereprettyplease123456\x10\x02\"\nciphertextMAC_01234567890_01234567890_HERE";
        let result = Message::try_from(bytes.as_slice());
        assert_let!(Ok(message) = result);

        let Message { version, ratchet_key, chain_index, ciphertext, mac } = message;

        assert_eq!(version, VERSION);
        assert_eq!(ratchet_key.as_bytes(), b"ratchetkeyhereprettyplease123456");
        assert_eq!(chain_index, 2);
        assert_eq!(ciphertext, b"ciphertext");
        assert_eq!(mac.as_bytes(), b"MAC_01234567890_01234567890_HERE");
    }

    #[test]
    fn from_bytes_too_short() {
        let bytes = vec![MAC_TRUNCATED_VERSION, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = Message::try_from(bytes);
        assert_matches!(result, Err(DecodeError::MessageTooShort(9)));
    }

    #[test]
    fn from_bytes_decoding_error() {
        let bytes = vec![MAC_TRUNCATED_VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = Message::try_from(bytes);
        assert_matches!(result, Err(DecodeError::ProtoBufError(_)));
    }

    #[test]
    fn from_bytes_invalid_tag() {
        let bytes = [
            VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let result = Message::try_from(bytes.to_vec());
        assert_matches!(result, Err(DecodeError::ProtoBufError(_)));
    }
}
