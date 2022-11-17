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

use matrix_pickle::Decode;
use serde::{Deserialize, Serialize};
use x25519_dalek::SharedSecret;

use super::{
    chain_key::RemoteChainKey,
    root_key::{RemoteRootKey, RootKey},
};
use crate::{types::Curve25519SecretKey, Curve25519PublicKey};

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub(super) struct RatchetKey(Curve25519SecretKey);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RatchetPublicKey(Curve25519PublicKey);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Decode)]
#[serde(transparent)]
pub struct RemoteRatchetKey(Curve25519PublicKey);

impl RatchetKey {
    pub fn new() -> Self {
        Self(Curve25519SecretKey::new())
    }

    pub fn diffie_hellman(&self, other: &RemoteRatchetKey) -> SharedSecret {
        self.0.diffie_hellman(&other.0)
    }
}

impl From<Curve25519SecretKey> for RatchetKey {
    fn from(key: Curve25519SecretKey) -> Self {
        Self(key)
    }
}

impl From<[u8; 32]> for RatchetPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        RatchetPublicKey(Curve25519PublicKey::from(bytes))
    }
}

impl From<[u8; 32]> for RemoteRatchetKey {
    fn from(bytes: [u8; 32]) -> Self {
        RemoteRatchetKey(Curve25519PublicKey::from(bytes))
    }
}

impl From<Curve25519PublicKey> for RemoteRatchetKey {
    fn from(key: Curve25519PublicKey) -> Self {
        RemoteRatchetKey(key)
    }
}

impl AsRef<Curve25519PublicKey> for RatchetPublicKey {
    fn as_ref(&self) -> &Curve25519PublicKey {
        &self.0
    }
}

impl From<&RatchetKey> for RatchetPublicKey {
    fn from(r: &RatchetKey) -> Self {
        RatchetPublicKey(Curve25519PublicKey::from(&r.0))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct Ratchet {
    root_key: RootKey,
    ratchet_key: RatchetKey,
}

impl Ratchet {
    pub fn new(root_key: RootKey) -> Self {
        let ratchet_key = RatchetKey::new();

        Self { root_key, ratchet_key }
    }

    pub fn new_with_ratchet_key(root_key: RootKey, ratchet_key: RatchetKey) -> Self {
        Self { root_key, ratchet_key }
    }

    pub fn advance(&self, remote_key: RemoteRatchetKey) -> (RemoteRootKey, RemoteChainKey) {
        let (remote_root_key, remote_chain_key) =
            self.root_key.advance(&self.ratchet_key, &remote_key);

        (remote_root_key, remote_chain_key)
    }

    pub fn ratchet_key(&self) -> &RatchetKey {
        &self.ratchet_key
    }
}
