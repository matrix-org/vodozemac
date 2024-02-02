// Copyright 2024 Damir Jelić
// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use crate::{types::KyberPublicKey, Curve25519PublicKey, KeyId};

/// A struct to configure how Olm sessions should work under the hood.
/// Currently only the MAC truncation behaviour can be configured.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    pub(super) version: Version,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum Version {
    V1(SessionKeysV1),
    V2(SessionKeysV1),
    VPQ(SessionKeysPQ),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionKeysV1 {
    pub remote_identity_key: Curve25519PublicKey,
    pub one_time_key: Curve25519PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionKeysPQ {
    pub remote_identity_key: Curve25519PublicKey,
    pub one_time_key: Option<Curve25519PublicKey>,
    pub signed_pre_key: Curve25519PublicKey,
    pub kyber_key: KyberPublicKey,
    pub kyber_key_id: KeyId,
}

impl SessionConfig {
    /// Get the numeric version of this `SessionConfig`.
    pub fn version(&self) -> u8 {
        match self.version {
            Version::V1(_) => 1,
            Version::V2(_) => 2,
            Version::VPQ(_) => 3,
        }
    }

    /// Create a `SessionConfig` for the Olm version 1. This version of Olm will
    /// use AES-256 and HMAC with a truncated MAC to encrypt individual
    /// messages. The MAC will be truncated to 8 bytes.
    pub fn version_1(
        remote_identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Self {
        SessionConfig { version: Version::V1(SessionKeysV1 { remote_identity_key, one_time_key }) }
    }

    /// Create a `SessionConfig` for the Olm version 2. This version of Olm will
    /// use AES-256 and HMAC to encrypt individual messages. The MAC won't be
    /// truncated.
    pub fn version_2(
        remote_identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Self {
        SessionConfig { version: Version::V2(SessionKeysV1 { remote_identity_key, one_time_key }) }
    }

    pub fn version_pq(
        remote_identity_key: Curve25519PublicKey,
        signed_pre_key: Curve25519PublicKey,
        one_time_key: Option<Curve25519PublicKey>,
        kyber_key: KyberPublicKey,
        kyber_key_id: KeyId,
    ) -> Self {
        Self {
            version: Version::VPQ(SessionKeysPQ {
                remote_identity_key,
                one_time_key,
                signed_pre_key,
                kyber_key,
                kyber_key_id,
            }),
        }
    }
}
