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

use serde::{Deserialize, Serialize};

use super::{
    chain_key::ChainKey,
    message_key::MessageKey,
    ratchet::{Ratchet, RatchetPublicKey, RemoteRatchetKey},
    receiver_chain::ReceiverChain,
    root_key::{RemoteRootKey, RootKey},
};
use crate::olm::{messages::Message, shared_secret::Shared3DHSecret};

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub(super) struct DoubleRatchet {
    inner: DoubleRatchetState,
}

impl DoubleRatchet {
    pub fn next_message_key(&mut self) -> MessageKey {
        match &mut self.inner {
            DoubleRatchetState::Inactive(ratchet) => {
                let mut ratchet = ratchet.activate();

                let message_key = ratchet.next_message_key();
                self.inner = DoubleRatchetState::Active(ratchet);

                message_key
            }
            DoubleRatchetState::Active(ratchet) => ratchet.next_message_key(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Message {
        self.next_message_key().encrypt(plaintext)
    }

    pub fn encrypt_truncated_mac(&mut self, plaintext: &[u8]) -> Message {
        self.next_message_key().encrypt_truncated_mac(plaintext)
    }

    pub fn active(shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand();

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        let ratchet = ActiveDoubleRatchet {
            active_ratchet: Ratchet::new(root_key),
            symmetric_key_ratchet: chain_key,
        };

        Self { inner: ratchet.into() }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_ratchet_and_chain_key(ratchet: Ratchet, chain_key: ChainKey) -> Self {
        Self {
            inner: ActiveDoubleRatchet {
                active_ratchet: ratchet,
                symmetric_key_ratchet: chain_key,
            }
            .into(),
        }
    }

    pub fn inactive(root_key: RemoteRootKey, ratchet_key: RemoteRatchetKey) -> Self {
        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key };

        Self { inner: ratchet.into() }
    }

    pub fn advance(&mut self, ratchet_key: RemoteRatchetKey) -> (DoubleRatchet, ReceiverChain) {
        let (ratchet, receiver_chain) = match &self.inner {
            DoubleRatchetState::Active(r) => r.advance(ratchet_key),
            DoubleRatchetState::Inactive(r) => {
                let ratchet = r.activate();
                // Advancing an inactive ratchet shouldn't be possible since the
                // other side did not yet receive our new ratchet key.
                //
                // This will likely end up in a decryption error but for
                // consistency sake and avoiding the leakage of our internal
                // state it's better to error out there.
                let ret = ratchet.advance(ratchet_key);

                self.inner = ratchet.into();

                ret
            }
        };

        (Self { inner: DoubleRatchetState::Inactive(ratchet) }, receiver_chain)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum DoubleRatchetState {
    Inactive(InactiveDoubleRatchet),
    Active(ActiveDoubleRatchet),
}

impl From<InactiveDoubleRatchet> for DoubleRatchetState {
    fn from(r: InactiveDoubleRatchet) -> Self {
        Self::Inactive(r)
    }
}

impl From<ActiveDoubleRatchet> for DoubleRatchetState {
    fn from(r: ActiveDoubleRatchet) -> Self {
        Self::Active(r)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct InactiveDoubleRatchet {
    root_key: RemoteRootKey,
    ratchet_key: RemoteRatchetKey,
}

impl InactiveDoubleRatchet {
    fn activate(&self) -> ActiveDoubleRatchet {
        let (root_key, chain_key, ratchet_key) = self.root_key.advance(&self.ratchet_key);
        let active_ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);

        ActiveDoubleRatchet { active_ratchet, symmetric_key_ratchet: chain_key }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct ActiveDoubleRatchet {
    active_ratchet: Ratchet,
    symmetric_key_ratchet: ChainKey,
}

impl ActiveDoubleRatchet {
    fn advance(&self, ratchet_key: RemoteRatchetKey) -> (InactiveDoubleRatchet, ReceiverChain) {
        let (root_key, remote_chain) = self.active_ratchet.advance(ratchet_key);

        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key };
        let receiver_chain = ReceiverChain::new(ratchet_key, remote_chain);

        (ratchet, receiver_chain)
    }

    fn ratchet_key(&self) -> RatchetPublicKey {
        RatchetPublicKey::from(self.active_ratchet.ratchet_key())
    }

    fn next_message_key(&mut self) -> MessageKey {
        self.symmetric_key_ratchet.create_message_key(self.ratchet_key())
    }
}
