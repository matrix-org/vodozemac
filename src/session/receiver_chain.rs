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

use arrayvec::ArrayVec;

use super::{chain_key::RemoteChainKey, message_key::RemoteMessageKey, ratchet::RemoteRatchetKey};
use crate::messages::InnerMessage;

const MAX_MESSAGE_GAP: u64 = 2000;
const MAX_MESSAGE_KEYS: usize = 40;

struct MessageKeyStore {
    inner: ArrayVec<RemoteMessageKey, MAX_MESSAGE_KEYS>,
}

impl MessageKeyStore {
    fn new() -> Self {
        Self { inner: ArrayVec::new() }
    }

    fn push(&mut self, message_key: RemoteMessageKey) {
        if self.inner.is_full() {
            self.inner.pop_at(0);
        }

        self.inner.push(message_key)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn merge(&mut self, mut store: MessageKeyStore) {
        for key in store.inner.drain(..) {
            self.push(key);
        }
    }

    fn get_message_key(&self, chain_index: u64) -> Option<&RemoteMessageKey> {
        self.inner.iter().find(|k| k.chain_index() == chain_index)
    }

    fn remove_message_key(&mut self, chain_index: u64) {
        self.inner.retain(|k| k.chain_index() != chain_index);
    }
}

impl Default for MessageKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) struct ReceiverChain {
    ratchet_key: RemoteRatchetKey,
    hkdf_ratchet: RemoteChainKey,
    skipped_message_keys: MessageKeyStore,
}

impl ReceiverChain {
    pub fn new(ratchet_key: RemoteRatchetKey, chain_key: RemoteChainKey) -> Self {
        ReceiverChain {
            ratchet_key,
            hkdf_ratchet: chain_key,
            skipped_message_keys: Default::default(),
        }
    }

    pub fn decrypt(
        &mut self,
        message: &InnerMessage,
        chain_index: u64,
        ciphertext: &[u8],
        mac: [u8; 8],
    ) -> Vec<u8> {
        if chain_index.saturating_sub(self.hkdf_ratchet.chain_index()) > MAX_MESSAGE_GAP {
            todo!()
        } else if self.hkdf_ratchet.chain_index() > chain_index {
            if let Some(message_key) = self.skipped_message_keys.get_message_key(chain_index) {
                let plaintext = message_key.decrypt(message, ciphertext, mac);

                // TODO only remove the message key if decryption succeeds.
                self.skipped_message_keys.remove_message_key(chain_index);

                plaintext
            } else {
                todo!()
            }
        } else {
            let mut ratchet = self.hkdf_ratchet.clone();
            let mut skipped_keys = MessageKeyStore::new();

            // Advance the ratchet up until our desired point.
            while ratchet.chain_index() < chain_index {
                if chain_index - ratchet.chain_index() > MAX_MESSAGE_KEYS as u64 {
                    ratchet.advance();
                } else {
                    let key = ratchet.create_message_key();
                    skipped_keys.push(key);
                }
            }

            // Create now our desired message key
            let message_key = ratchet.create_message_key();
            let plaintext = message_key.decrypt(message, ciphertext, mac);

            // TODO if decryption fails, don't update our ratchet
            self.hkdf_ratchet = ratchet;
            self.skipped_message_keys.merge(skipped_keys);

            plaintext
        }
    }

    pub fn belongs_to(&self, ratchet_key: &RemoteRatchetKey) -> bool {
        &self.ratchet_key == ratchet_key
    }
}
