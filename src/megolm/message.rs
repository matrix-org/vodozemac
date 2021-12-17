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

use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use prost::Message;

use crate::{
    cipher::Mac,
    messages::{DecodeError, Encode},
};

const VERSION: u8 = 3;

pub(super) struct MegolmMessage(Vec<u8>);

impl MegolmMessage {
    const MAC_LOCATION: usize = Mac::TRUNCATED_LEN + SIGNATURE_LENGTH;

    pub fn new(ciphertext: Vec<u8>, message_index: u32) -> Self {
        let message = InnerMegolmMessage { message_index, ciphertext };

        Self(message.encode_manual())
    }

    pub fn decode(message: Vec<u8>) -> Result<(Self, DecodedMegolmMessage), DecodeError> {
        let version = *message.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != VERSION {
            Err(DecodeError::InvalidVersion(VERSION, version))
        } else if message.len() < 1 + Self::MAC_LOCATION {
            Err(DecodeError::MessageToShort(message.len()))
        } else {
            let inner =
                InnerMegolmMessage::decode(&message[1..message.len() - Self::MAC_LOCATION])?;

            let mac_location = message.len() - Self::MAC_LOCATION;
            let signature_location = message.len() - SIGNATURE_LENGTH;

            let mac_slice = &message[mac_location..mac_location + Mac::TRUNCATED_LEN];
            let signature_slice = &message[signature_location..];

            let mut mac = [0u8; Mac::TRUNCATED_LEN];
            mac.copy_from_slice(mac_slice);
            let signature = Signature::from_bytes(signature_slice)?;

            let decoded = DecodedMegolmMessage {
                ciphertext: inner.ciphertext,
                message_index: inner.message_index,
                mac,
                signature,
            };

            Ok((Self(message), decoded))
        }
    }

    fn mac_start(&self) -> usize {
        self.0.len() - Self::MAC_LOCATION
    }

    fn mac_slice(&self) -> &[u8] {
        let mac_start = self.mac_start();

        &self.0[mac_start..mac_start + Mac::TRUNCATED_LEN]
    }

    fn signature_slice(&self) -> &[u8] {
        let signature_start = self.signature_start();
        &self.0[signature_start..]
    }

    pub fn bytes_for_mac(&self) -> &[u8] {
        &self.0[..self.mac_start()]
    }

    pub fn append_mac(&mut self, mac: Mac) {
        let mac = mac.truncate();
        let mac_start = self.mac_start();

        self.0[mac_start..mac_start + mac.len()].copy_from_slice(&mac);
    }

    fn signature_start(&self) -> usize {
        self.0.len() - SIGNATURE_LENGTH
    }

    pub fn bytes_for_signing(&self) -> &[u8] {
        &self.0[..self.signature_start()]
    }

    pub fn append_signature(&mut self, signature: Signature) {
        let signature_start = self.signature_start();
        self.0[signature_start..].copy_from_slice(&signature.to_bytes());
    }
}

pub(crate) struct DecodedMegolmMessage {
    pub ciphertext: Vec<u8>,
    pub message_index: u32,
    pub mac: [u8; 8],
    pub signature: Signature,
}

impl AsRef<[u8]> for MegolmMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Message, PartialEq)]
struct InnerMegolmMessage {
    #[prost(uint32, tag = "1")]
    pub message_index: u32,
    #[prost(bytes, tag = "2")]
    pub ciphertext: Vec<u8>,
}

impl InnerMegolmMessage {
    const INDEX_TAG: &'static [u8; 1] = b"\x08";
    const CIPHER_TAG: &'static [u8; 1] = b"\x12";

    fn encode_manual(&self) -> Vec<u8> {
        // Prost optimizes away the chain index if it's 0, libolm can't decode
        // this, so encode our messages the pedestrian way instead.
        let index = self.message_index.encode();
        let ciphertext_len = self.ciphertext.len().encode();

        [
            [VERSION].as_ref(),
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &self.ciphertext,
            &[0u8; Mac::TRUNCATED_LEN],
            &[0u8; SIGNATURE_LENGTH],
        ]
        .concat()
    }
}
