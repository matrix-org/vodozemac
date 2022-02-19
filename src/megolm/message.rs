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

use prost::Message;

use crate::{
    cipher::Mac,
    types::Ed25519Signature,
    utilities::{base64_decode, base64_encode, VarInt},
    DecodeError,
};

const VERSION: u8 = 3;

pub struct MegolmMessage {
    pub ciphertext: Vec<u8>,
    pub message_index: u32,
    pub mac: [u8; Mac::TRUNCATED_LEN],
    pub signature: Ed25519Signature,
}

impl MegolmMessage {
    const MESSAGE_SUFFIX_LENGTH: usize = Mac::TRUNCATED_LEN + Ed25519Signature::LENGTH;

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn message_index(&self) -> u32 {
        self.message_index
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    pub fn from_base64(message: &str) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut message = self.encode_message();

        message.extend(&self.mac);
        message.extend(self.signature.to_bytes());

        message
    }

    pub fn from_bytes(message: Vec<u8>) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    fn encode_message(&self) -> Vec<u8> {
        let message = ProtobufMegolmMessage {
            message_index: self.message_index,
            ciphertext: self.ciphertext.clone(),
        };

        message.encode_manual()
    }

    pub(super) fn new(ciphertext: Vec<u8>, message_index: u32) -> Self {
        Self {
            ciphertext,
            message_index,
            mac: [0u8; Mac::TRUNCATED_LEN],
            signature: Ed25519Signature::from_slice(&[0; Ed25519Signature::LENGTH])
                .expect("Can't create an empty signature"),
        }
    }

    pub(super) fn to_mac_bytes(&self) -> Vec<u8> {
        self.encode_message()
    }

    pub(super) fn to_signature_bytes(&self) -> Vec<u8> {
        let mut message = self.encode_message();
        message.extend(self.mac);

        message
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
        let version = *message.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != VERSION {
            Err(DecodeError::InvalidVersion(VERSION, version))
        } else if message.len() < Self::MESSAGE_SUFFIX_LENGTH + 2 {
            Err(DecodeError::MessageTooShort(message.len()))
        } else {
            let inner = ProtobufMegolmMessage::decode(
                &message[1..message.len() - Self::MESSAGE_SUFFIX_LENGTH],
            )?;

            let mac_location = message.len() - Self::MESSAGE_SUFFIX_LENGTH;
            let signature_location = message.len() - Ed25519Signature::LENGTH;

            let mac_slice = &message[mac_location..mac_location + Mac::TRUNCATED_LEN];
            let signature_slice = &message[signature_location..];

            let mut mac = [0u8; Mac::TRUNCATED_LEN];
            mac.copy_from_slice(mac_slice);
            let signature = Ed25519Signature::from_slice(signature_slice)?;

            Ok(MegolmMessage {
                ciphertext: inner.ciphertext,
                message_index: inner.message_index,
                mac,
                signature,
            })
        }
    }
}

#[derive(Clone, Message, PartialEq)]
struct ProtobufMegolmMessage {
    #[prost(uint32, tag = "1")]
    pub message_index: u32,
    #[prost(bytes, tag = "2")]
    pub ciphertext: Vec<u8>,
}

impl ProtobufMegolmMessage {
    const INDEX_TAG: &'static [u8; 1] = b"\x08";
    const CIPHER_TAG: &'static [u8; 1] = b"\x12";

    fn encode_manual(&self) -> Vec<u8> {
        // Prost optimizes away the message index if it's 0, libolm can't decode
        // this, so encode our messages the pedestrian way instead.
        let index = self.message_index.to_var_int();
        let ciphertext_len = self.ciphertext.len().to_var_int();

        [
            [VERSION].as_ref(),
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &self.ciphertext,
        ]
        .concat()
    }
}
