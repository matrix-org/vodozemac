// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{utilities::base64_encode, Curve25519PublicKey};

/// The set of keys that were used to establish the session.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionKeys {
    /// Alice's identity key.
    pub identity_key: Curve25519PublicKey,
    /// Alice's ephemeral (base) key.
    pub base_key: Curve25519PublicKey,
    /// Bob's identity key.
    pub other_identity_key: Curve25519PublicKey,
    /// Bob's OTK which Alice used.
    pub signed_pre_key: Curve25519PublicKey,
    /// Bob's OTK which Alice used, if any.
    pub one_time_key: Option<Curve25519PublicKey>,
}

impl SessionKeys {
    /// Returns the globally unique session ID which these [`SessionKeys`]
    /// will produce.
    ///
    /// A session ID is the SHA256 of the concatenation of the session keys
    /// which were used to establish the session: the account's identity key,
    /// the ephemeral base key, the signed pre-key and the one-time key (if
    /// any).
    ///
    /// Due to the construction, every session ID is (probabilistically)
    /// globally unique.
    pub fn session_id(&self) -> String {
        let sha = Sha256::new();

        let digest = sha
            .chain_update(self.identity_key.as_bytes())
            .chain_update(self.base_key.as_bytes())
            .chain_update(self.signed_pre_key.as_bytes());

        let digest = if let Some(otk) = self.one_time_key {
            digest.chain_update(otk.as_bytes())
        } else {
            digest
        };

        let digest = digest.finalize();

        base64_encode(digest)
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("identity_key", &self.identity_key.to_base64())
            .field("base_key", &self.base_key.to_base64())
            .field("other_identity_key", &self.other_identity_key.to_base64())
            .field("signed_pre_key", &self.signed_pre_key.to_base64())
            .field("one_time_key", &self.one_time_key.map(|x| x.to_base64()))
            .finish()
    }
}

/// Represents the session keys as received over the network in the Olm and
/// Interolm protocols.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct OlmSessionKeys {
    /// Alice's identity key.
    pub identity_key: Curve25519PublicKey,
    /// Alice's ephemeral (base) key.
    pub base_key: Curve25519PublicKey,
    /// Bob's OTK which Alice used.
    pub one_time_key: Curve25519PublicKey,
}

impl OlmSessionKeys {
    /// Returns the globally unique session ID which these [`SessionKeysWire`]
    /// will produce.
    ///
    /// A session ID is the SHA256 of the concatenation of three session keys
    /// which were used to establish the session: the account's identity key,
    /// the ephemeral base key and the one-time key.
    ///
    /// Due to the construction, every session ID is (probabilistically)
    /// globally unique.
    pub fn session_id(&self) -> String {
        let sha = Sha256::new();

        let digest = sha
            .chain_update(self.identity_key.as_bytes())
            .chain_update(self.base_key.as_bytes())
            .chain_update(self.one_time_key.as_bytes());

        let digest = digest.finalize();

        base64_encode(digest)
    }
}

impl std::fmt::Debug for OlmSessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeysWire")
            .field("identity_key", &self.identity_key.to_base64())
            .field("base_key", &self.base_key.to_base64())
            .field("signed_pre_key", &self.one_time_key.to_base64())
            .finish()
    }
}

impl From<SessionKeys> for OlmSessionKeys {
    fn from(value: SessionKeys) -> Self {
        Self {
            identity_key: value.identity_key,
            base_key: value.base_key,
            one_time_key: value.signed_pre_key,
        }
    }
}
