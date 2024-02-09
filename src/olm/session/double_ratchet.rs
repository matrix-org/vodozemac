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
    chain_key::{ChainKey, RemoteChainKey},
    message_key::MessageKey,
    ratchet::{Ratchet, RatchetKey, RatchetPublicKey, RemoteRatchetKey},
    receiver_chain::ReceiverChain,
    root_key::{RemoteRootKey, RootKey},
};
use crate::olm::{
    messages::Message,
    session_config::SessionCreator,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    InterolmMessage, SessionConfig, SessionKeys,
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub(super) struct DoubleRatchet {
    inner: DoubleRatchetState,
}

impl DoubleRatchet {
    pub fn chain_index(&self) -> Option<u64> {
        match &self.inner {
            DoubleRatchetState::Inactive(_) => None,
            DoubleRatchetState::Active(r) => Some(r.symmetric_key_ratchet.index()),
        }
    }

    pub fn next_message_key(&mut self, config: &SessionConfig) -> MessageKey {
        match &mut self.inner {
            DoubleRatchetState::Inactive(ratchet) => {
                let mut ratchet = ratchet.activate(config);

                let message_key = ratchet.next_message_key();
                self.inner = DoubleRatchetState::Active(ratchet);

                message_key
            }
            DoubleRatchetState::Active(ratchet) => ratchet.next_message_key(),
        }
    }

    pub fn encrypt(&mut self, config: &SessionConfig, plaintext: &[u8]) -> Message {
        self.next_message_key(config).encrypt(plaintext)
    }

    pub fn encrypt_truncated_mac(&mut self, config: &SessionConfig, plaintext: &[u8]) -> Message {
        self.next_message_key(config).encrypt_truncated_mac(plaintext)
    }

    #[cfg(feature = "interolm")]
    pub fn encrypt_interolm(
        &mut self,
        config: &SessionConfig,
        session_creator: SessionCreator,
        session_keys: &SessionKeys,
        previous_index: u32,
        plaintext: &[u8],
    ) -> InterolmMessage {
        self.next_message_key(config).encrypt_interolm(
            session_keys,
            session_creator,
            previous_index,
            plaintext,
        )
    }

    pub fn active(config: &SessionConfig, shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand(config);

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        let ratchet = ActiveDoubleRatchet {
            active_ratchet: Ratchet::new(root_key),
            symmetric_key_ratchet: chain_key,
        };

        Self { inner: ratchet.into() }
    }

    pub fn inactive(root_key: RemoteRootKey, ratchet_key: RemoteRatchetKey) -> Self {
        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key };

        Self { inner: ratchet.into() }
    }

    #[cfg(feature = "interolm")]
    pub fn active_interolm(
        config: &SessionConfig,
        shared_secret: Shared3DHSecret,
        their_ratchet_key: RemoteRatchetKey,
    ) -> (Self, ReceiverChain) {
        // Interolm considers the second item of this KDF expansion to be the receiver
        // chain key, and therefore the ratchet is created in the inactive
        // state. This is different from Olm where the ratchet starts in the
        // active state since we derive the sender chain key directly from the
        // shared secret. Therefore when talking to an Interolm implementation,
        // to obtain an active ratchet, we start off in the inactive state and
        // then immediately advance a step.
        let (remote_root_key, remote_chain_key) = shared_secret.expand(config);
        let remote_root_key = RemoteRootKey::new(remote_root_key);
        let remote_chain_key = RemoteChainKey::new(remote_chain_key);
        let receiver_chain = ReceiverChain::new(their_ratchet_key, remote_chain_key);

        let inactive_ratchet =
            InactiveDoubleRatchet { root_key: remote_root_key, ratchet_key: their_ratchet_key };
        let active_ratchet = inactive_ratchet.activate(config);

        let dh_ratchet = Self { inner: active_ratchet.into() };

        (dh_ratchet, receiver_chain)
    }

    #[cfg(feature = "interolm")]
    pub fn inactive_interolm(
        config: &SessionConfig,
        shared_secret: RemoteShared3DHSecret,
        our_ratchet_key: RatchetKey,
        their_ratchet_key: RemoteRatchetKey,
    ) -> (Self, ReceiverChain) {
        let (root_key, chain_key) = shared_secret.expand(config);

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        let ratchet = ActiveDoubleRatchet {
            active_ratchet: Ratchet::new_with_ratchet_key(root_key, our_ratchet_key),
            symmetric_key_ratchet: chain_key,
        };

        let (inner_ratchet, receiver_chain) = ratchet.advance(config, their_ratchet_key);

        (Self { inner: inner_ratchet.into() }, receiver_chain)
    }

    pub fn advance(
        &mut self,
        config: &SessionConfig,
        ratchet_key: RemoteRatchetKey,
    ) -> (DoubleRatchet, ReceiverChain) {
        let (ratchet, receiver_chain) = match &self.inner {
            DoubleRatchetState::Active(r) => r.advance(config, ratchet_key),
            DoubleRatchetState::Inactive(r) => {
                let ratchet = r.activate(config);
                // Advancing an inactive ratchet shouldn't be possible since the
                // other side did not yet receive our new ratchet key.
                //
                // This will likely end up in a decryption error but for
                // consistency sake and avoiding the leakage of our internal
                // state it's better to error out there.
                let ret = ratchet.advance(config, ratchet_key);

                self.inner = ratchet.into();

                ret
            }
        };

        (Self { inner: DoubleRatchetState::Inactive(ratchet) }, receiver_chain)
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
    fn activate(&self, config: &SessionConfig) -> ActiveDoubleRatchet {
        let (root_key, chain_key, ratchet_key) = self.root_key.advance(config, &self.ratchet_key);
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
    fn advance(
        &self,
        config: &SessionConfig,
        ratchet_key: RemoteRatchetKey,
    ) -> (InactiveDoubleRatchet, ReceiverChain) {
        let (root_key, remote_chain) = self.active_ratchet.advance(config, ratchet_key);

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
