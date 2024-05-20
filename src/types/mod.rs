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

impl KeyId {
    pub fn to_base64(self) -> String {
        crate::utilities::base64_encode(self.0.to_be_bytes())
    }
}

/// Error type describing failures that can happen when we try decode or use a
/// cryptographic key.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Failed decoding a public key from base64: {}", .0)]
    Base64Error(#[from] base64::DecodeError),
    #[error("Failed to decode a private key from base64: {}", .0)]
    Base64PrivateKey(#[from] base64ct::Error),
    #[error(
        "Failed decoding {key_type} key from base64: \
        Invalid number of bytes for {key_type}, expected {expected_length}, got {length}."
    )]
    InvalidKeyLength { key_type: &'static str, expected_length: usize, length: usize },
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// At least one of the keys did not have contributory behaviour and the
    /// resulting shared secret would have been insecure.
    #[error("At least one of the keys did not have contributory behaviour")]
    NonContributoryKey,
}

#[cfg(test)]
mod test {
    use crate::KeyId;

    #[test]
    fn key_id_to_base64() {
        assert_eq!(KeyId(0).to_base64(), "AAAAAAAAAAA");
        assert_eq!(KeyId(7).to_base64(), "AAAAAAAAAAc");
    }

    #[test]
    fn key_id_to_string() {
        assert_eq!(String::from(KeyId(0)), "AAAAAAAAAAA");
        assert_eq!(String::from(KeyId(7)), "AAAAAAAAAAc");
    }
}
