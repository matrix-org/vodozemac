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

use super::{chain_key::RemoteChainKey, ratchet::RemoteRatchetKey};
use crate::messages::InnerMessage;

pub(super) struct ReceiverChain {
    ratchet_key: RemoteRatchetKey,
    hkdf_ratchet: RemoteChainKey,
}

impl ReceiverChain {
    pub fn new(ratchet_key: RemoteRatchetKey, chain_key: RemoteChainKey) -> Self {
        ReceiverChain { ratchet_key, hkdf_ratchet: chain_key }
    }

    pub fn decrypt(&mut self, message: &InnerMessage, ciphertext: &[u8], mac: [u8; 8]) -> Vec<u8> {
        let message_key = self.hkdf_ratchet.create_message_key();
        message_key.decrypt(message, ciphertext, mac)
    }

    pub fn belongs_to(&self, ratchet_key: &RemoteRatchetKey) -> bool {
        &self.ratchet_key == ratchet_key
    }
}
