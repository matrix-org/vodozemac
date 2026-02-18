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

use std::fmt::Debug;

use matrix_pickle::Decode;
use serde::{Deserialize, Serialize};
use x25519_dalek::SharedSecret;

use super::{
    chain_key::RemoteChainKey,
    root_key::{RemoteRootKey, RootKey},
};
use crate::{Curve25519PublicKey, types::Curve25519SecretKey};

/// A ratchet key which we created ourselves.
///
/// A new ratchet key is created each time the conversation changes direction,
/// and used to calculate the [root key](RootKey) for the new sender chain.
/// The public part of the sender's ratchet key is sent to the recipient in each
/// message.
///
/// Since this is *our own* key, we have both the secret and public parts of the
/// key.
///
/// The [Olm spec](https://gitlab.matrix.org/matrix-org/olm/blob/master/docs/olm.md) refers to
/// ratchet keys as `T`<sub>`i`</sub>.
#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub(super) struct RatchetKey(Curve25519SecretKey);

/// The public part of a [`RatchetKey`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RatchetPublicKey(Curve25519PublicKey);

/// A ratchet key which was created by the other side.
///
/// See [`RatchetKey`] for explanation about ratchet keys in general. Since this
/// is the other side's key, we have only the public part of the key.
#[derive(Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize, Decode)]
#[serde(transparent)]
pub struct RemoteRatchetKey(Curve25519PublicKey);

impl Debug for RemoteRatchetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl RatchetKey {
    pub fn new() -> Self {
        Self(Curve25519SecretKey::new())
    }

    pub fn diffie_hellman(&self, other: &RemoteRatchetKey) -> SharedSecret {
        self.0.diffie_hellman(&other.0)
    }
}

impl Default for RatchetKey {
    fn default() -> Self {
        Self::new()
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

/// Information about the root key ratchet, while our sender chain is active.
///
/// We only have one of these while the double ratchet is "active" - ie, while
/// we are encrypting messages. It stores the information necessary to calculate
/// the *next* root key; in particular, the root key of our active chain
/// `R`<sub>`i`</sub>, and our own ratchet key `T`<sub>`i`</sub>.
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

    pub const fn new_with_ratchet_key(root_key: RootKey, ratchet_key: RatchetKey) -> Self {
        Self { root_key, ratchet_key }
    }

    pub fn advance(&self, remote_key: RemoteRatchetKey) -> Option<(RemoteRootKey, RemoteChainKey)> {
        let (remote_root_key, remote_chain_key) =
            self.root_key.advance(&self.ratchet_key, &remote_key)?;

        Some((remote_root_key, remote_chain_key))
    }

    pub const fn ratchet_key(&self) -> &RatchetKey {
        &self.ratchet_key
    }
}

#[cfg(test)]
mod test {
    use super::RatchetKey;
    use crate::{Curve25519SecretKey, olm::RatchetPublicKey};

    #[test]
    fn ratchet_key_from_curve_25519_secret_key() {
        let bytes = b"aaaaaaaaaaaaaaawaaaaaaaaaaaaaaaa";
        let key = RatchetKey::from(Curve25519SecretKey::from_slice(bytes));
        assert_eq!(key.0.to_bytes().as_ref(), bytes);
    }

    #[test]
    fn ratchet_public_key_from_bytes() {
        let bytes = b"aaaaaaaaaaaaaaawaaaaaaaaaaaaaaaa";
        let key = RatchetPublicKey::from(*bytes);
        assert_eq!(key.0.to_bytes().as_ref(), bytes);
    }
}
