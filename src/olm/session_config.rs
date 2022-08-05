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

/// A struct to configure how Olm sessions should work under the hood.
/// Currently only the MAC truncation behaviour can be configured.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    pub(super) version: Version,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum Version {
    V1 = 1,
    V2 = 2,
}

impl SessionConfig {
    /// Get the numeric version of this `SessionConfig`.
    pub fn version(&self) -> u8 {
        self.version as u8
    }

    /// Create a `SessionConfig` for the Olm version 1. This version of Olm will
    /// use AES-256 and HMAC with a truncated MAC to encrypt individual
    /// messages. The MAC will be truncated to 8 bytes.
    pub fn version_1() -> Self {
        SessionConfig { version: Version::V1 }
    }

    /// Create a `SessionConfig` for the Olm version 2. This version of Olm will
    /// use AES-256 and HMAC to encrypt individual messages. The MAC won't be
    /// truncated.
    pub fn version_2() -> Self {
        SessionConfig { version: Version::V2 }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self::version_2()
    }
}
