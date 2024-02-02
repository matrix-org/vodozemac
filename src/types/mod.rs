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

use std::fmt::Display;

mod curve25519;
mod ed25519;

pub(crate) use curve25519::{Curve25519Keypair, Curve25519KeypairPickle};
pub use curve25519::{Curve25519PublicKey, Curve25519SecretKey};
pub use ed25519::{
    Ed25519Keypair, Ed25519KeypairPickle, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature,
    SignatureError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use x25519_dalek::SharedSecret;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyId(pub(super) u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        value.to_base64()
    }
}

impl From<u32> for KeyId {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl KeyId {
    pub fn to_base64(self) -> String {
        crate::utilities::base64_encode(self.0.to_be_bytes())
    }

    pub fn from_base64(base64: &str) -> Result<Self, KeyIdError> {
        let id = u64::from_be_bytes(
            crate::utilities::base64_decode(base64)?.try_into().map_err(KeyIdError::OutOfRange)?,
        );
        Ok(Self(id))
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Error type describing failures when decoding a key ID.
#[derive(Error, Debug)]
pub enum KeyIdError {
    #[error("Failed decoding key ID from base64: {}", .0)]
    Base64Error(#[from] base64::DecodeError),
    #[error("The key ID was not a valid u64 integer. Key ID bytes: {:?}", .0)]
    OutOfRange(Vec<u8>),
}

impl Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("KeyId({0})", self.0))
    }
}

/// Error type describing failures that can happen when we try decode or use a
/// cryptographic key.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Failed decoding a public key from base64: {}", .0)]
    Base64Error(#[from] base64::DecodeError),
    #[error(
        "Failed decoding {key_type} key from base64: \
        Invalid number of bytes for {key_type}, expected {expected_length}, got {length}."
    )]
    InvalidKeyLength { key_type: &'static str, expected_length: usize, length: usize },
    #[error("The key is in the 33-byte format but the marker byte is wrong: expect 0x5, got {}", .0)]
    InvalidKeyFormat(u8),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// At least one of the keys did not have contributory behaviour and the
    /// resulting shared secret would have been insecure.
    #[error("At least one of the keys did not have contributory behaviour")]
    NonContributoryKey,
}
