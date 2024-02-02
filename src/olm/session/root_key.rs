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
use zeroize::Zeroize;

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    ratchet::{RatchetKey, RemoteRatchetKey},
};
use crate::olm::{session_config::Version, SessionConfig};

const ADVANCEMENT_SEED_OLM: &[u8; 11] = b"OLM_RATCHET";
const ADVANCEMENT_SEED_INTEROLM: &[u8; 11] = b"OLM_RATCHET";

#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[serde(transparent)]
#[zeroize(drop)]
pub(crate) struct RootKey {
    pub key: Box<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub(crate) struct RemoteRootKey {
    pub key: Box<[u8; 32]>,
}

fn kdf(
    info: &[u8],
    root_key: &[u8; 32],
    ratchet_key: &RatchetKey,
    remote_ratchet_key: &RemoteRatchetKey,
) -> Box<[u8; 64]> {
    let shared_secret = ratchet_key.diffie_hellman(remote_ratchet_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(root_key.as_ref()), shared_secret.as_bytes());
    let mut output = Box::new([0u8; 64]);

    hkdf.expand(info, output.as_mut_slice()).expect("Can't expand");

    output
}

fn kdf_olm(
    root_key: &[u8; 32],
    ratchet_key: &RatchetKey,
    remote_ratchet_key: &RemoteRatchetKey,
) -> Box<[u8; 64]> {
    kdf(ADVANCEMENT_SEED_OLM, root_key, ratchet_key, remote_ratchet_key)
}

fn kdf_interolm(
    root_key: &[u8; 32],
    ratchet_key: &RatchetKey,
    remote_ratchet_key: &RemoteRatchetKey,
) -> Box<[u8; 64]> {
    kdf(ADVANCEMENT_SEED_INTEROLM, root_key, ratchet_key, remote_ratchet_key)
}

impl RemoteRootKey {
    pub(super) fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
    }

    pub(super) fn advance(
        &self,
        config: &SessionConfig,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RootKey, ChainKey, RatchetKey) {
        let ratchet_key = RatchetKey::new();

        let output = match config.version {
            Version::V1 | Version::V2 => kdf_olm(&self.key, &ratchet_key, remote_ratchet_key),
            Version::Interolm(..) => kdf_interolm(&self.key, &ratchet_key, remote_ratchet_key),
        };

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        let chain_key = ChainKey::new(chain_key);
        let root_key = RootKey::new(root_key);

        (root_key, chain_key, ratchet_key)
    }
}

impl RootKey {
    pub(super) fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes }
    }

    pub(super) fn advance(
        &self,
        config: &SessionConfig,
        old_ratchet_key: &RatchetKey,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RemoteRootKey, RemoteChainKey) {
        let output = match config.version {
            Version::V1 | Version::V2 => kdf_olm(&self.key, old_ratchet_key, remote_ratchet_key),
            Version::Interolm(..) => kdf_interolm(&self.key, old_ratchet_key, remote_ratchet_key),
        };

        let mut chain_key = Box::new([0u8; 32]);
        let mut root_key = Box::new([0u8; 32]);

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        let root_key = RemoteRootKey::new(root_key);
        let chain_key = RemoteChainKey::new(chain_key);

        (root_key, chain_key)
    }
}
