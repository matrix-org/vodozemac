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

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    ratchet::{RatchetKey, RemoteRatchetKey},
};

const ADVANCEMENT_SEED: &[u8; 11] = b"OLM_RATCHET";

/// A root key for one of our own sender chains.
///
/// A new root key `R`<sub>`i`</sub> is calculated each time the conversation
/// changes direction, based on the previous root key `R`<sub>`i-1`</sub> and
/// the previous and new [ratchet keys](RatchetKey) `T`<sub>`i-1`</sub>,
/// `T`<sub>`i`</sub>. It is used only to calculate the *next* root key
/// `R`<sub>`i+1`</sub> and [chain key](ChainKey) `C`<sub>`i+1`</sub>.
///
/// This struct holds the root key corresponding to chains where we are the
/// sender. See also [`RemoteRootKey`].
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub(crate) struct RootKey {
    pub key: Box<[u8; 32]>,
}

/// A root key for one of the other side's sender chains.
///
/// See [`RootKey`] for information on root keys. This struct holds the root key
/// corresponding to chains where the other side is the sender.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct RemoteRootKey {
    pub key: Box<[u8; 32]>,
}

fn kdf(
    root_key: &[u8; 32],
    ratchet_key: &RatchetKey,
    remote_ratchet_key: &RemoteRatchetKey,
) -> Box<[u8; 64]> {
    let shared_secret = ratchet_key.diffie_hellman(remote_ratchet_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(root_key.as_ref()), shared_secret.as_bytes());
    let mut output = Box::new([0u8; 64]);

    #[allow(clippy::expect_used)]
    hkdf.expand(ADVANCEMENT_SEED, output.as_mut_slice())
        .expect("We should be able to expand the shared secret.");

    output
}

impl RemoteRootKey {
    pub(super) const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
    }

    /// Get the [`RemoteRootKey`] as a boxed slice of bytes.
    #[cfg(feature = "libolm-compat")]
    #[allow(clippy::borrowed_box)]
    pub fn as_bytes(&self) -> &Box<[u8; 32]> {
        &self.key
    }

    pub(super) fn advance(
        &self,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RootKey, ChainKey, RatchetKey) {
        let ratchet_key = RatchetKey::new();
        let output = kdf(&self.key, &ratchet_key, remote_ratchet_key);

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        chain_key.copy_from_slice(&output[32..]);
        root_key.copy_from_slice(&output[..32]);

        let chain_key = ChainKey::new(chain_key);
        let root_key = RootKey::new(root_key);

        (root_key, chain_key, ratchet_key)
    }
}

impl RootKey {
    pub(super) const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
    }

    /// Get the [`RootKey`] as a boxed slice of bytes.
    #[cfg(feature = "libolm-compat")]
    #[allow(clippy::borrowed_box)]
    pub fn as_bytes(&self) -> &Box<[u8; 32]> {
        &self.key
    }

    pub(super) fn advance(
        &self,
        old_ratchet_key: &RatchetKey,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RemoteRootKey, RemoteChainKey) {
        let output = kdf(&self.key, old_ratchet_key, remote_ratchet_key);

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        let root_key = RemoteRootKey::new(root_key);
        let chain_key = RemoteChainKey::new(chain_key);

        (root_key, chain_key)
    }
}
