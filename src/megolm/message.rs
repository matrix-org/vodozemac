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

use prost::Message;

use crate::{cipher::Mac, messages::Encode};

pub(super) struct MegolmMessage(Vec<u8>);

impl MegolmMessage {
    pub fn new(ciphertext: Vec<u8>, message_index: u32) -> Self {
        let message = InnerMegolmMessage { message_index: message_index.into(), ciphertext };

        Self(message.encode_manual())
    }

    fn mac_start(&self) -> usize {
        self.0.len() - (Mac::TRUNCATED_LEN + ed25519_dalek::SIGNATURE_LENGTH)
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
        self.0.len() - ed25519_dalek::SIGNATURE_LENGTH
    }

    pub fn bytes_for_signing(&self) -> &[u8] {
        &self.0[..self.signature_start()]
    }

    pub fn append_signature(&mut self, signature: ed25519_dalek::Signature) {
        let signature_start = self.signature_start();
        self.0[signature_start..].copy_from_slice(&signature.to_bytes());
    }
}

impl AsRef<[u8]> for MegolmMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Message, PartialEq)]
struct InnerMegolmMessage {
    #[prost(uint64, tag = "8")]
    pub message_index: u64,
    #[prost(bytes, tag = "12")]
    pub ciphertext: Vec<u8>,
}

impl InnerMegolmMessage {
    const VERSION: u8 = 3;

    const INDEX_TAG: &'static [u8; 1] = b"\x08";
    const CIPHER_TAG: &'static [u8; 1] = b"\x12";

    fn encode_manual(&self) -> Vec<u8> {
        // Prost optimizes away the chain index if it's 0, libolm can't decode
        // this, so encode our messages the pedestrian way instead.
        let index = self.message_index.encode();
        let ciphertext_len = self.ciphertext.len().encode();

        [
            [Self::VERSION].as_ref(),
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &self.ciphertext,
            &[0u8; Mac::TRUNCATED_LEN],
            &[0u8; ed25519_dalek::SIGNATURE_LENGTH],
        ]
        .concat()
    }
}
