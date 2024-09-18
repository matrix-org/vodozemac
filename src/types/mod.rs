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

/// A unique identifier for a one-time [`Curve25519PublicKey`].
///
/// This identifier uses an internal counter to track the order in which
/// one-time keys are generated.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyId(pub(super) u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        value.to_base64()
    }
}

impl KeyId {
    /// Encodes the [`KeyId`] in Base64.
    ///
    /// The internal counter is represented in big-endian format and then
    /// encoded using Base64.
    pub fn to_base64(self) -> String {
        crate::utilities::base64_encode(self.0.to_be_bytes())
    }
}

/// Error type for failures that may occur when decoding or using a
/// cryptographic key.
#[derive(Error, Debug)]
pub enum KeyError {
    /// Failed to correctly decode a public key that was encoded in Base64.
    #[error("Failed to decode a public key from Base64: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Failed to correctly decode a private key that was encoded in Base64.
    #[error("Failed to decode a private key from Base64: {0}")]
    Base64PrivateKey(#[from] base64ct::Error),

    /// The Base64 encoded key does not contain the expected number of bytes.
    #[error(
        "Failed to decode {key_type} key from Base64: \
        Invalid number of bytes for {key_type}, expected {expected_length}, got {length}."
    )]
    InvalidKeyLength {
        /// The type of key being decoded.
        key_type: &'static str,
        /// The expected length of the key.
        expected_length: usize,
        /// The actual length of the key.
        length: usize,
    },
    /// Unable to decompress the curve point `r` from an [`Ed25519PublicKey`].
    ///
    /// For more details, see [RFC 8032, Section 5.1.3](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3).
    #[error(transparent)]
    Signature(#[from] SignatureError),

    /// One or more keys lacked contributory behavior in the Diffie-Hellman
    /// operation, resulting in an insecure shared secret.
    ///
    /// For more details on contributory behavior please refer to the
    /// [`x25519_dalek::SharedSecret::was_contributory()`] method.
    #[error(
        "One or more keys lacked contributory behavior in the Diffie-Hellman operation, \
         resulting in an insecure shared secret"
    )]
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
