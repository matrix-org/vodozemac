// Copyright 2021 The Matrix.org Foundation C.I.C.
// Copyright 2022 Damir Jelić
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

use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    cipher::{Cipher, Mac, MessageMac},
    types::{Ed25519Keypair, Ed25519Signature},
    utilities::{base64_decode, base64_encode, extract_mac, VarInt},
    DecodeError,
};
#[cfg(feature = "low-level-api")]
use crate::{Ed25519PublicKey, SignatureError};

const MAC_TRUNCATED_VERSION: u8 = 3;
const VERSION: u8 = 4;

/// An encrypted Megolm message.
///
/// Contains metadata that is required to find the correct ratchet state of a
/// [`InboundGroupSession`] necessary to decryp the message.
///
/// [`InboundGroupSession`]: crate::megolm::InboundGroupSession
#[derive(Clone, PartialEq, Eq)]
pub struct MegolmMessage {
    pub(super) version: u8,
    pub(super) ciphertext: Vec<u8>,
    pub(super) message_index: u32,
    pub(super) mac: MessageMac,
    pub(super) signature: Ed25519Signature,
}

impl MegolmMessage {
    const MESSAGE_TRUNCATED_SUFFIX_LENGTH: usize = Mac::TRUNCATED_LEN + Ed25519Signature::LENGTH;
    const MESSAGE_SUFFIX_LENGTH: usize = Mac::LENGTH + Ed25519Signature::LENGTH;

    /// The actual ciphertext of the message.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The index of the message that was used when the message was encrypted.
    pub fn message_index(&self) -> u32 {
        self.message_index
    }

    /// Get the megolm message's mac.
    pub fn mac(&self) -> &[u8] {
        self.mac.as_bytes()
    }

    /// Get a reference to the megolm message's signature.
    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Try to decode the given byte slice as a [`MegolmMessage`].
    ///
    /// The expected format of the byte array is described in the
    /// [`MegolmMessage::to_bytes()`] method.
    pub fn from_bytes(message: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    /// Encode the [`MegolmMessage`] as an array of bytes.
    ///
    /// Megolm messages consist of a one byte version, followed by a variable
    /// length payload, a fixed length message authentication code, and a fixed
    /// length signature.
    ///
    /// ```text
    /// +---+------------------------------------+-----------+------------------+
    /// | V | Payload Bytes                      | MAC Bytes | Signature Bytes  |
    /// +---+------------------------------------+-----------+------------------+
    /// 0   1                                    N          N+8                N+72   bytes
    /// ```
    ///
    /// The payload uses a format based on the Protocol Buffers encoding. It
    /// consists of the following key-value pairs:
    ///
    ///    **Name**  |**Tag**|**Type**|            **Meaning**
    /// :-----------:|:-----:|:------:|:---------------------------------------:
    /// Message-Index|  0x08 | Integer|The index of the ratchet, i
    /// Cipher-Text  |  0x12 | String |The cipher-text, Xi, of the message
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut message = self.encode_message();

        message.extend(self.mac.as_bytes());
        message.extend(self.signature.to_bytes());

        message
    }

    /// Try to decode the given string as a [`MegolmMessage`].
    ///
    /// The string needs to be a base64 encoded byte array that follows the
    /// format described in the [`MegolmMessage::to_bytes()`] method.
    pub fn from_base64(message: &str) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    /// Encode the [`MegolmMessage`] as a string.
    ///
    /// This method first calls [`MegolmMessage::to_bytes()`] and then encodes
    /// the resulting byte array as a string using base64 encoding.
    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    /// Set the signature of the message, verifying that the signature matches
    /// the signing key.
    #[cfg(feature = "low-level-api")]
    pub fn add_signature(
        &mut self,
        signature: Ed25519Signature,
        signing_key: Ed25519PublicKey,
    ) -> Result<(), SignatureError> {
        signing_key.verify(&self.to_signature_bytes(), &signature)?;

        self.signature = signature;

        Ok(())
    }

    fn encode_message(&self) -> Vec<u8> {
        let message = ProtobufMegolmMessage {
            message_index: self.message_index,
            ciphertext: self.ciphertext.clone(),
        };

        message.encode_manual(self.version)
    }

    fn set_mac(&mut self, mac: Mac) {
        match self.mac {
            MessageMac::Truncated(_) => self.mac = mac.truncate().into(),
            MessageMac::Full(_) => self.mac = mac.into(),
        }
    }

    /// Create a new [`MegolmMessage`] with the given plaintext and keys.
    #[cfg(feature = "low-level-api")]
    pub fn encrypt(
        message_index: u32,
        cipher: &Cipher,
        signing_key: &Ed25519Keypair,
        plaintext: &[u8],
    ) -> Self {
        MegolmMessage::encrypt_truncated_mac(message_index, cipher, signing_key, plaintext)
    }

    /// Implementation of [`MegolmMessage::encrypt`] that is used by rest of the
    /// crate.
    pub(super) fn encrypt_full_mac(
        message_index: u32,
        cipher: &Cipher,
        signing_key: &Ed25519Keypair,
        plaintext: &[u8],
    ) -> Self {
        let ciphertext = cipher.encrypt(plaintext);

        let message = Self {
            version: VERSION,
            ciphertext,
            message_index,
            mac: Mac([0u8; Mac::LENGTH]).into(),
            signature: Ed25519Signature::from_slice(&[0; Ed25519Signature::LENGTH])
                .expect("Can't create an empty signature"),
        };

        Self::encrypt_helper(cipher, signing_key, message)
    }

    pub(super) fn encrypt_truncated_mac(
        message_index: u32,
        cipher: &Cipher,
        signing_key: &Ed25519Keypair,
        plaintext: &[u8],
    ) -> Self {
        let ciphertext = cipher.encrypt(plaintext);

        let message = Self {
            version: MAC_TRUNCATED_VERSION,
            ciphertext,
            message_index,
            mac: [0u8; Mac::TRUNCATED_LEN].into(),
            signature: Ed25519Signature::from_slice(&[0; Ed25519Signature::LENGTH])
                .expect("Can't create an empty signature"),
        };

        Self::encrypt_helper(cipher, signing_key, message)
    }

    fn encrypt_helper(
        cipher: &Cipher,
        signing_key: &Ed25519Keypair,
        mut message: MegolmMessage,
    ) -> Self {
        let mac = cipher.mac(&message.to_mac_bytes());
        message.set_mac(mac);

        let signature = signing_key.sign(&message.to_signature_bytes());
        message.signature = signature;

        message
    }

    pub(super) fn to_mac_bytes(&self) -> Vec<u8> {
        self.encode_message()
    }

    pub(super) fn to_signature_bytes(&self) -> Vec<u8> {
        let mut message = self.encode_message();
        message.extend(self.mac.as_bytes());

        message
    }
}

impl Serialize for MegolmMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let message = self.to_base64();
        serializer.serialize_str(&message)
    }
}

impl<'de> Deserialize<'de> for MegolmMessage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ciphertext = String::deserialize(d)?;
        Self::from_base64(&ciphertext).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for MegolmMessage {
    type Error = DecodeError;

    fn try_from(message: &str) -> Result<Self, Self::Error> {
        let decoded = base64_decode(message)?;

        Self::try_from(decoded)
    }
}

impl TryFrom<Vec<u8>> for MegolmMessage {
    type Error = DecodeError;

    fn try_from(message: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(message.as_slice())
    }
}

impl TryFrom<&[u8]> for MegolmMessage {
    type Error = DecodeError;

    fn try_from(message: &[u8]) -> Result<Self, Self::Error> {
        let version = *message.first().ok_or(DecodeError::MissingVersion)?;

        let suffix_length = match version {
            VERSION => Self::MESSAGE_SUFFIX_LENGTH,
            MAC_TRUNCATED_VERSION => Self::MESSAGE_TRUNCATED_SUFFIX_LENGTH,
            _ => return Err(DecodeError::InvalidVersion(VERSION, version)),
        };

        if message.len() < suffix_length + 2 {
            Err(DecodeError::MessageTooShort(message.len()))
        } else {
            let inner = ProtobufMegolmMessage::decode(
                message
                    .get(1..message.len() - suffix_length)
                    .ok_or_else(|| DecodeError::MessageTooShort(message.len()))?,
            )?;

            let signature_location = message.len() - Ed25519Signature::LENGTH;
            let signature_slice = &message[signature_location..];
            let signature = Ed25519Signature::from_slice(signature_slice)?;

            let mac_slice = &message[message.len() - suffix_length..];
            let mac = extract_mac(mac_slice, version == MAC_TRUNCATED_VERSION);

            Ok(MegolmMessage {
                version,
                ciphertext: inner.ciphertext,
                message_index: inner.message_index,
                mac,
                signature,
            })
        }
    }
}

impl Debug for MegolmMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { version, ciphertext: _, message_index, mac: _, signature: _ } = self;

        f.debug_struct("MegolmMessage")
            .field("version", version)
            .field("message_index", message_index)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Message, PartialEq, Eq)]
struct ProtobufMegolmMessage {
    #[prost(uint32, tag = "1")]
    pub message_index: u32,
    #[prost(bytes, tag = "2")]
    pub ciphertext: Vec<u8>,
}

impl ProtobufMegolmMessage {
    const INDEX_TAG: &'static [u8; 1] = b"\x08";
    const CIPHER_TAG: &'static [u8; 1] = b"\x12";

    fn encode_manual(&self, version: u8) -> Vec<u8> {
        // Prost optimizes away the message index if it's 0, libolm can't decode
        // this, so encode our messages the pedestrian way instead.
        let index = self.message_index.to_var_int();
        let ciphertext_len = self.ciphertext.len().to_var_int();

        [
            [version].as_ref(),
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &self.ciphertext,
        ]
        .concat()
    }
}
