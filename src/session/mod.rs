// Copyright 2021 Damir Jelić
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

mod chain_key;
mod double_ratchet;
mod message_key;
mod ratchet;
mod root_key;

use arrayvec::ArrayVec;
use chain_key::RemoteChainKey;
use double_ratchet::{LocalDoubleRatchet, RemoteDoubleRatchet};
use ratchet::RemoteRatchetKey;
use root_key::RemoteRootKey;
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as Curve25519PublicKey;

use crate::{
    messages::{InnerMessage, InnerPreKeyMessage, Message, OlmMessage, PreKeyMessage},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    utilities::{decode, encode},
};

const MAX_REMOTE_RATCHETS: usize = 5;

struct RatchetStore {
    inner: ArrayVec<RemoteDoubleRatchet, MAX_REMOTE_RATCHETS>,
}

impl RatchetStore {
    fn new() -> Self {
        Self { inner: ArrayVec::new() }
    }

    fn push(&mut self, ratchet: RemoteDoubleRatchet) {
        if self.inner.is_full() {
            self.inner.pop_at(0);
        }

        self.inner.push(ratchet)
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn find_ratchet(&mut self, ratchet_key: &RemoteRatchetKey) -> Option<&mut RemoteDoubleRatchet> {
        self.inner.iter_mut().find(|r| r.belongs_to(ratchet_key))
    }
}

impl Default for RatchetStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Session {
    session_keys: SessionKeys,
    sending_ratchet: LocalDoubleRatchet,
    receiving_ratchets: RatchetStore,
}

impl Session {
    pub(super) fn new(shared_secret: Shared3DHSecret, session_keys: SessionKeys) -> Self {
        let local_ratchet = LocalDoubleRatchet::active(shared_secret);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_ratchets: Default::default(),
        }
    }

    pub(super) fn new_remote(
        shared_secret: RemoteShared3DHSecret,
        remote_ratchet_key: Curve25519PublicKey,
        session_keys: SessionKeys,
    ) -> Self {
        let (root_key, remote_chain_key) = shared_secret.expand();

        let remote_ratchet_key = RemoteRatchetKey::from(remote_ratchet_key);
        let root_key = RemoteRootKey::new(root_key);
        let remote_chain_key = RemoteChainKey::new(remote_chain_key);

        let local_ratchet = LocalDoubleRatchet::inactive(root_key, remote_ratchet_key.clone());
        let remote_ratchet = RemoteDoubleRatchet::new(remote_ratchet_key, remote_chain_key);

        let mut ratchet_store = RatchetStore::new();
        ratchet_store.push(remote_ratchet);

        Self { session_keys, sending_ratchet: local_ratchet, receiving_ratchets: ratchet_store }
    }

    pub fn pickle(&self) -> String {
        todo!()
    }

    pub fn unpickle(_pickle: String) -> Self {
        todo!()
    }

    pub fn session_id(&self) -> String {
        let sha = Sha256::new();

        let digest = sha
            .chain_update(self.session_keys.identity_key.as_bytes())
            .chain_update(self.session_keys.base_key.as_bytes())
            .chain_update(self.session_keys.one_time_key.as_bytes())
            .finalize();

        encode(digest)
    }

    pub fn encrypt(&mut self, plaintext: &str) -> OlmMessage {
        let message = match &mut self.sending_ratchet {
            LocalDoubleRatchet::Inactive(ratchet) => {
                let mut ratchet = ratchet.activate();

                let message = ratchet.encrypt(plaintext.as_bytes());
                self.sending_ratchet = LocalDoubleRatchet::Active(ratchet);

                message
            }
            LocalDoubleRatchet::Active(ratchet) => ratchet.encrypt(plaintext.as_bytes()),
        };

        if self.receiving_ratchets.is_empty() {
            let message = InnerPreKeyMessage::from_parts(
                &self.session_keys.one_time_key,
                &self.session_keys.base_key,
                &self.session_keys.identity_key,
                message.into_vec(),
            )
            .into_vec();

            OlmMessage::PreKey(PreKeyMessage { inner: encode(message) })
        } else {
            let message = message.into_vec();

            OlmMessage::Normal(Message { inner: encode(message) })
        }
    }

    pub fn decrypt(&mut self, message: &OlmMessage) -> String {
        let decrypted = match message {
            OlmMessage::Normal(m) => {
                let message = decode(&m.inner).unwrap();
                self.decrypt_normal(message)
            }
            OlmMessage::PreKey(m) => {
                let message = decode(&m.inner).unwrap();
                self.decrypt_prekey(message)
            }
        };

        String::from_utf8_lossy(&decrypted).to_string()
    }

    fn decrypt_prekey(&mut self, message: Vec<u8>) -> Vec<u8> {
        let message = InnerPreKeyMessage::from(message);
        let (_, _, _, message) = message.decode().unwrap();

        self.decrypt_normal(message)
    }

    fn decrypt_normal(&mut self, message: Vec<u8>) -> Vec<u8> {
        let message = InnerMessage::from(message);
        let decoded = message.decode().unwrap();

        let ratchet_key = RemoteRatchetKey::from(decoded.ratchet_key);

        // TODO try to use existing message keys.
        if let Some(ratchet) = self.receiving_ratchets.find_ratchet(&ratchet_key) {
            ratchet.decrypt(&message, &decoded.ciphertext, decoded.mac)
        } else {
            let (sending_ratchet, mut remote_ratchet) = self.sending_ratchet.advance(ratchet_key);

            // TODO don't update the state if the message doesn't decrypt
            let plaintext = remote_ratchet.decrypt(&message, &decoded.ciphertext, decoded.mac);

            self.sending_ratchet = LocalDoubleRatchet::Inactive(sending_ratchet);
            self.receiving_ratchets.push(remote_ratchet);

            plaintext
        }
    }
}
