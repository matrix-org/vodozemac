// Copyright 2021 Damir Jelić, Denis Kasak
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

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

use super::{
    chain_key::RemoteChainKey, message_key::RemoteMessageKey, ratchet::RemoteRatchetKey,
    DecryptionError,
};
use crate::olm::{
    session_config::{SessionCreator, Version},
    AnyNormalMessage, SessionConfig, SessionKeys,
};

const MAX_MESSAGE_GAP: u64 = 2000;
const MAX_MESSAGE_KEYS: usize = 40;

#[derive(Serialize, Deserialize, Clone)]
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

enum FoundMessageKey<'a> {
    Existing(&'a RemoteMessageKey),
    New(Box<(RemoteChainKey, MessageKeyStore, RemoteMessageKey)>),
}

impl FoundMessageKey<'_> {
    fn decrypt(
        &self,
        config: &SessionConfig,
        session_keys: &SessionKeys,
        session_creator: SessionCreator,
        message: AnyNormalMessage<'_>,
    ) -> Result<Vec<u8>, DecryptionError> {
        let message_key = match self {
            FoundMessageKey::Existing(m) => m,
            FoundMessageKey::New(m) => &m.2,
        };

        match message {
            AnyNormalMessage::Native(message) => match config.version {
                Version::V1 => message_key.decrypt_truncated_mac(message),
                Version::V2 => message_key.decrypt(message),
                #[cfg(feature = "interolm")]
                Version::Interolm(..) => {
                    Err(DecryptionError::WrongAlgorithm("Interolm".into(), "Olm".into()))
                }
            },
            #[cfg(feature = "interolm")]
            AnyNormalMessage::Interolm(message) => match config.version {
                Version::V1 | Version::V2 => {
                    Err(DecryptionError::WrongAlgorithm("Olm".into(), "Interolm".into()))
                }
                Version::Interolm(..) => {
                    message_key.decrypt_interolm(session_keys, session_creator, message)
                }
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct ReceiverChain {
    ratchet_key: RemoteRatchetKey,
    pub(super) hkdf_ratchet: RemoteChainKey,
    skipped_message_keys: MessageKeyStore,
}

impl Debug for ReceiverChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { ratchet_key, hkdf_ratchet, skipped_message_keys } = self;

        f.debug_struct("ReceiverChain")
            .field("ratchet_key", &ratchet_key)
            .field("chain_index", &hkdf_ratchet.chain_index())
            .field("skipped_message_keys", &skipped_message_keys.inner)
            .finish_non_exhaustive()
    }
}

impl ReceiverChain {
    pub fn new(ratchet_key: RemoteRatchetKey, chain_key: RemoteChainKey) -> Self {
        ReceiverChain {
            ratchet_key,
            hkdf_ratchet: chain_key,
            skipped_message_keys: Default::default(),
        }
    }

    fn find_message_key(&self, chain_index: u64) -> Result<FoundMessageKey<'_>, DecryptionError> {
        let message_gap = chain_index.saturating_sub(self.hkdf_ratchet.chain_index());

        if message_gap > MAX_MESSAGE_GAP {
            Err(DecryptionError::TooBigMessageGap(message_gap, MAX_MESSAGE_GAP))
        } else if self.hkdf_ratchet.chain_index() > chain_index {
            self.skipped_message_keys
                .get_message_key(chain_index)
                .map(FoundMessageKey::Existing)
                .ok_or(DecryptionError::MissingMessageKey(chain_index))
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

            Ok(FoundMessageKey::New(Box::new((ratchet, skipped_keys, message_key))))
        }
    }

    pub fn decrypt(
        &mut self,
        config: &SessionConfig,
        session_keys: &SessionKeys,
        session_creator: SessionCreator,
        message: AnyNormalMessage<'_>,
    ) -> Result<Vec<u8>, DecryptionError> {
        let chain_index = message.chain_index();
        let message_key = self.find_message_key(chain_index)?;

        let plaintext = message_key.decrypt(config, session_keys, session_creator, message)?;

        match message_key {
            FoundMessageKey::Existing(m) => {
                let chain_index = m.chain_index();
                self.skipped_message_keys.remove_message_key(chain_index)
            }
            FoundMessageKey::New(m) => {
                let (ratchet, skipped_keys, _) = *m;

                self.hkdf_ratchet = ratchet;
                self.skipped_message_keys.merge(skipped_keys);
            }
        }

        Ok(plaintext)
    }

    #[cfg(feature = "libolm-compat")]
    pub fn ratchet_key(&self) -> RemoteRatchetKey {
        self.ratchet_key
    }

    #[cfg(feature = "libolm-compat")]
    pub fn insert_message_key(&mut self, message_key: RemoteMessageKey) {
        self.skipped_message_keys.push(message_key)
    }

    pub fn belongs_to(&self, ratchet_key: &RemoteRatchetKey) -> bool {
        &self.ratchet_key == ratchet_key
    }
}
