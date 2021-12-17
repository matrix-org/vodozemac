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

use ed25519_dalek::{PublicKey, Signature, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use super::{message::MegolmMessage, ratchet::Ratchet, SESSION_KEY_VERSION};
use crate::{cipher::Cipher, utilities::base64_decode};

pub struct InboundGroupSession {
    initial_ratchet: Ratchet,
    latest_ratchet: Ratchet,
    signing_key: PublicKey,
}

pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

impl InboundGroupSession {
    pub fn new(session_key: String) -> Self {
        let decoded = base64_decode(session_key).unwrap();
        let mut cursor = Cursor::new(decoded);

        let mut version = [0u8; 1];
        let mut index = [0u8; 4];
        let mut ratchet = [0u8; 128];
        let mut public_key = [0u8; PUBLIC_KEY_LENGTH];
        let mut signature = [0u8; SIGNATURE_LENGTH];

        cursor.read_exact(&mut version).unwrap();

        if version[0] != SESSION_KEY_VERSION {
            todo!()
        }

        cursor.read_exact(&mut index).unwrap();
        cursor.read_exact(&mut ratchet).unwrap();
        cursor.read_exact(&mut public_key).unwrap();
        cursor.read_exact(&mut signature).unwrap();

        let index = u32::from_le_bytes(index);
        let initial_ratchet = Ratchet::from_bytes(ratchet, index);
        let latest_ratchet = initial_ratchet.clone();

        let signing_key = PublicKey::from_bytes(&public_key).unwrap();
        let signature = Signature::from_bytes(&signature).unwrap();

        let decoded = cursor.into_inner();

        signing_key.verify(&decoded[..decoded.len() - 64], &signature).unwrap();

        Self { initial_ratchet, latest_ratchet, signing_key }
    }

    pub fn decrypt(&mut self, ciphertext: &str) -> DecryptedMessage {
        let decoded = base64_decode(ciphertext).unwrap();
        let (ciphertext, message_index, mac, signature) = MegolmMessage::decode(&decoded);

        self.signing_key.verify(&decoded[..decoded.len() - 64], &signature).unwrap();

        let ratchet = if self.initial_ratchet.index() == message_index {
            &self.initial_ratchet
        } else if self.latest_ratchet.index() == message_index {
            &self.latest_ratchet
        } else if self.latest_ratchet.index() < message_index {
            self.latest_ratchet.advance_to(message_index);
            &self.latest_ratchet
        } else if self.initial_ratchet.index() < message_index {
            self.latest_ratchet = self.initial_ratchet.clone();
            self.latest_ratchet.advance_to(message_index);
            &self.latest_ratchet
        } else {
            todo!()
        };

        let cipher = Cipher::new_megolm(ratchet.as_bytes());

        cipher.verify_mac(&decoded[..decoded.len() - 72], &mac).unwrap();
        let plaintext = String::from_utf8_lossy(&cipher.decrypt(&ciphertext).unwrap()).to_string();

        DecryptedMessage { plaintext, message_index }
    }

    pub fn export_at(&mut self) -> String {
        todo!()
    }
}
