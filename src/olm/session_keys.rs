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

use matrix_pickle::Decode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Curve25519PublicKey, utilities::base64_encode};

/// The set of keys that were used to establish the Olm Session,
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Decode)]
pub struct SessionKeys {
    /// The long-term [`Curve25519PublicKey`] of the session initiator.
    pub identity_key: Curve25519PublicKey,
    /// The ephemeral [`Curve25519PublicKey`] created by the session initiator
    /// to establish the session.
    pub base_key: Curve25519PublicKey,
    /// The one-time [`Curve25519PublicKey`] that the initiator downloaded from
    /// a key server, which was previously created and published by the
    /// recipient.
    pub one_time_key: Curve25519PublicKey,
}

impl SessionKeys {
    /// Returns the globally unique session ID which these [`SessionKeys`] will
    /// produce.
    ///
    /// A session ID is the SHA256 of the concatenation of three `SessionKeys`,
    /// the account's identity key, the ephemeral base key and the one-time
    /// key which is used to establish the session.
    ///
    /// Due to the construction, every session ID is (probabilistically)
    /// globally unique.
    pub fn session_id(&self) -> String {
        let sha = Sha256::new();

        let digest = sha
            .chain_update(self.identity_key.as_bytes())
            .chain_update(self.base_key.as_bytes())
            .chain_update(self.one_time_key.as_bytes())
            .finalize();

        base64_encode(digest)
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("identity_key", &self.identity_key.to_base64())
            .field("base_key", &self.base_key.to_base64())
            .field("one_time_key", &self.one_time_key.to_base64())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use insta::assert_debug_snapshot;

    use super::SessionKeys;
    use crate::Curve25519PublicKey;

    #[test]
    fn snapshot_session_keys_debug() {
        let key = Curve25519PublicKey::from_bytes([0; 32]);

        let session_keys = SessionKeys { identity_key: key, base_key: key, one_time_key: key };

        assert_debug_snapshot!(session_keys);
    }
}
