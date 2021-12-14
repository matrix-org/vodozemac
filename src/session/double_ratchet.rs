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

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    messages::OlmMessage,
    ratchet::{Ratchet, RatchetPublicKey, RemoteRatchet, RemoteRatchetKey},
    root_key::RemoteRootKey,
    shared_secret::Shared3DHSecret,
};

pub(super) enum LocalDoubleRatchet {
    Inactive(InactiveDoubleRatchet),
    Active(DoubleRatchet),
}

impl LocalDoubleRatchet {
    pub fn active(shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand();

        let local_ratchet = Ratchet::new(root_key);

        let local_ratchet = DoubleRatchet { dh_ratchet: local_ratchet, hkdf_ratchet: chain_key };

        LocalDoubleRatchet::Active(local_ratchet)
    }

    pub fn inactive(root_key: RemoteRootKey, ratchet_key: RemoteRatchetKey) -> Self {
        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key };

        Self::Inactive(ratchet)
    }

    pub fn advance(
        &self,
        ratchet_key: RemoteRatchetKey,
    ) -> (InactiveDoubleRatchet, RemoteDoubleRatchet) {
        if let LocalDoubleRatchet::Active(ratchet) = self {
            ratchet.advance(ratchet_key)
        } else {
            // TODO turn this into an error
            panic!("Can't advance an inactive ratchet");
        }
    }
}

pub(super) struct InactiveDoubleRatchet {
    root_key: RemoteRootKey,
    ratchet_key: RemoteRatchetKey,
}

impl InactiveDoubleRatchet {
    pub fn activate(&self) -> DoubleRatchet {
        let (root_key, chain_key, ratchet_key) = self.root_key.advance(&self.ratchet_key);
        let dh_ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);

        DoubleRatchet { dh_ratchet, hkdf_ratchet: chain_key }
    }
}

pub(super) struct DoubleRatchet {
    dh_ratchet: Ratchet,
    hkdf_ratchet: ChainKey,
}

impl DoubleRatchet {
    pub fn advance(
        &self,
        ratchet_key: RemoteRatchetKey,
    ) -> (InactiveDoubleRatchet, RemoteDoubleRatchet) {
        let (root_key, remote_ratchet, remote_chain) = self.dh_ratchet.advance(ratchet_key.clone());

        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key };

        let remote_ratchet =
            RemoteDoubleRatchet { dh_ratchet: remote_ratchet, hkdf_ratchet: remote_chain };

        (ratchet, remote_ratchet)
    }

    pub fn ratchet_key(&self) -> RatchetPublicKey {
        RatchetPublicKey::from(self.dh_ratchet.ratchet_key())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> OlmMessage {
        let message_key = self.hkdf_ratchet.create_message_key(self.ratchet_key());

        message_key.encrypt(plaintext)
    }
}

pub(super) struct RemoteDoubleRatchet {
    dh_ratchet: RemoteRatchet,
    hkdf_ratchet: RemoteChainKey,
}

impl RemoteDoubleRatchet {
    pub fn new(ratchet_key: RemoteRatchetKey, chain_key: RemoteChainKey) -> Self {
        let remote_ratchet = RemoteRatchet::new(ratchet_key);

        RemoteDoubleRatchet { dh_ratchet: remote_ratchet, hkdf_ratchet: chain_key }
    }

    pub fn decrypt(&mut self, message: &OlmMessage, ciphertext: &[u8], mac: [u8; 8]) -> Vec<u8> {
        let message_key = self.hkdf_ratchet.create_message_key();
        message_key.decrypt(message, ciphertext, mac)
    }

    pub fn belongs_to(&self, ratchet_key: &RemoteRatchetKey) -> bool {
        self.dh_ratchet.belongs_to(ratchet_key)
    }
}
