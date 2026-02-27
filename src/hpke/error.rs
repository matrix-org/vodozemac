// Copyright 2026 The Matrix.org Foundation C.I.C.
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

use thiserror::Error;

use crate::KeyError;

/// The error type for the HPKE message decoding failures.
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    /// The message failed to be decoded because the message isn't long enough.
    #[error("The message doesn't contain enough bytes to be decoded")]
    MessageIncomplete,
    /// The initial message could not have been decoded, the embedded Curve25519
    /// key is malformed.
    #[error("The embedded ephemeral Curve25519 key could not have been decoded: {0:?}")]
    KeyError(#[from] KeyError),
    /// The ciphertext is not valid base64.
    #[error("The ciphertext could not have been decoded from a base64 string: {0:?}")]
    Base64(#[from] base64::DecodeError),
}

/// The Error type for the HPKE submodule.
#[derive(Debug, Error)]
pub enum Error {
    /// Message decryption failed. Either the message was corrupted, the message
    /// was replayed, or the wrong key is being used to decrypt the message.
    #[error("Failed decrypting the message")]
    Decryption,
}
