// Copyright 2021 Denis Kasak, Damir Jelić
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

mod curve25519;
mod ed25519;

pub use curve25519::Curve25519PublicKey;
#[cfg(feature = "libolm-compat")]
pub(crate) use curve25519::Curve25519SecretKey;
pub(crate) use curve25519::{Curve25519Keypair, Curve25519KeypairPickle};
pub(crate) use ed25519::{Ed25519Keypair, Ed25519KeypairPickle, Ed25519KeypairUnpicklingError};
pub use ed25519::{Ed25519PublicKey, Ed25519Signature, SignatureError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyId(pub(super) u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        value.to_base64()
    }
}

impl KeyId {
    pub fn to_base64(self) -> String {
        crate::utilities::base64_encode(self.0.to_be_bytes())
    }
}

/// Error type describing failures that can happen when we try decode or use a
/// public key.
#[derive(Error, Debug)]
pub enum PublicKeyError {
    #[error("Failed decoding a public key from base64: {}", .0)]
    Base64Error(#[from] base64::DecodeError),
    #[error("Failed decoding curve25519 key from base64: \
             Invalid number of bytes for curve25519, expected {}, got {}.",
            Curve25519PublicKey::LENGTH, .0)]
    InvalidKeyLength(usize),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// At least one of the keys did not have contributory behaviour and the
    /// resulting shared secret would have been insecure.
    #[error("At least one of the keys did not have contributory behaviour")]
    NonContributoryKey,
}
