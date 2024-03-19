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

/// The sender side of a double-ratchet implementation.
///
/// While we are encrypting messages, we are in the "active" state. Here we need
/// to keep track of the latest chain key `C`<sub>`i`,`j`</sub> (so that we can
/// advance to the next one), and also the current root key `R`<sub>`i`</sub>
/// and our most recent ratchet key `T`<sub>`i`</sub> (so that we can calculate
/// the *next* root key).
///
/// Once we receive a message, we transition to the "inactive" state. Since we
/// don't handle decryption here (that's done in [`ReceiverChain`]), we don't
/// need to keep track of the sender's chain key. All we need is enough state so
/// that we can calculate the next root key once we start encrypting again:
/// specifically, the public part of the other side's ratchet key
/// `T`<sub>`i`</sub> which was sent to us in the message, and the remote root
/// key `R`<sub>`i`</sub>.
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

    /// Create a new `DoubleRatchet` instance, based on a newly-calculated
    /// shared secret.
    pub fn active(shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand();

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        let ratchet = ActiveDoubleRatchet {
            parent_ratchet_key: None, // First chain in a session lacks parent ratchet key
            active_ratchet: Ratchet::new(root_key),
            symmetric_key_ratchet: chain_key,
        };

        Self { inner: ratchet.into() }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_ratchet_and_chain_key(ratchet: Ratchet, chain_key: ChainKey) -> Self {
        Self {
            inner: ActiveDoubleRatchet {
                parent_ratchet_key: None, // libolm pickle did not record parent ratchet key
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

/// State of the sender-side ratchet when we have received a new chain from the
/// other side, and have not yet created a new chain of our own.
///
/// See [`DoubleRatchet`] for more explanation.
#[derive(Serialize, Deserialize, Clone)]
struct InactiveDoubleRatchet {
    root_key: RemoteRootKey,
    ratchet_key: RemoteRatchetKey,
}

impl InactiveDoubleRatchet {
    fn activate(&self) -> ActiveDoubleRatchet {
        let (root_key, chain_key, ratchet_key) = self.root_key.advance(&self.ratchet_key);
        let active_ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);

        ActiveDoubleRatchet {
            parent_ratchet_key: Some(self.ratchet_key),
            active_ratchet,
            symmetric_key_ratchet: chain_key,
        }
    }
}

/// State of the sender-side ratchet while we are in "encryption" mode: we are
/// encrypting our own messages and have not yet received any messages which
/// were created since we started this chain.
///
/// See [`DoubleRatchet`] for more explanation.
#[derive(Serialize, Deserialize, Clone)]
struct ActiveDoubleRatchet {
    /// The other side's most recent ratchet key, which was used to calculate
    /// the root key in `active_ratchet` and the chain key in
    /// `symmetric_key_ratchet`.
    ///
    /// If `active_ratchet` contains root key `R`<sub>`i`</sub> and our own
    /// ratchet key `T`<sub>`i`</sub>, this is `T`<sub>`i-1`</sub>.
    ///
    /// `None` means "unknown", either because this session has been restored
    /// from a pickle which did not record the parent session key, or because
    /// this is the first chain in the session.
    ///
    /// This is not required to implement the algorithm: it is maintained solely
    /// for diagnostic output.
    #[serde(default)]
    parent_ratchet_key: Option<RemoteRatchetKey>,

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
