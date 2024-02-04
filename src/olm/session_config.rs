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

use crate::KeyId;

/// Knobs for protocol configuration. Currently only used for switching between
/// different protocol versions (Olm v1, Olm v2 and Interolm).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    pub(super) version: Version,
}

#[cfg(feature = "interolm")]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterolmSessionMetadata {
    pub signed_pre_key_id: KeyId,
    pub one_time_key_id: Option<KeyId>,
    pub registration_id: u32,
}

#[cfg(feature = "interolm")]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionCreator {
    Us,
    Them,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum Version {
    V1,
    V2,
    #[cfg(feature = "interolm")]
    Interolm(InterolmSessionMetadata),
}

impl SessionConfig {
    /// Get the numeric representation of the session version.
    pub fn version(&self) -> u8 {
        match self.version {
            Version::V1 => 1,
            Version::V2 => 2,
            Version::Interolm(_) => 3,
        }
    }

    /// Create a `SessionConfig` for the Olm version 1. This version of Olm uses
    /// AES-256 and HMAC with an 8-byte truncated MAC for individual message
    /// encryption.
    pub fn version_1() -> Self {
        SessionConfig { version: Version::V1 }
    }

    /// Create a `SessionConfig` for the Olm version 2. This version of Olm uses
    /// AES-256 and HMAC to encrypt individual messages. The MAC is left
    /// untruncated (32 bytes).
    pub fn version_2() -> Self {
        SessionConfig { version: Version::V2 }
    }

    /// Create a `SessionConfig` for the Interolm protocol. Similarly to Olm v1,
    /// this uses AES-256 and a truncated 8-byte MAC.
    #[cfg(feature = "interolm")]
    pub fn version_interolm(
        registration_id: u32,
        signed_pre_key_id: KeyId,
        one_time_key_id: Option<KeyId>,
    ) -> Self {
        SessionConfig {
            version: Version::Interolm(InterolmSessionMetadata {
                signed_pre_key_id,
                one_time_key_id,
                registration_id,
            }),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self::version_2()
    }
}
