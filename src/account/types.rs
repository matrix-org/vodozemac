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

use ed25519_dalek::{Keypair, PublicKey as Ed25519PublicKey, Signer};
use rand::thread_rng;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret as Curve25519SecretKey};
use zeroize::Zeroize;

use crate::utilities::{base64_decode, base64_encode, DecodeError};

pub(super) struct Ed25519Keypair {
    inner: Keypair,
    encoded_public_key: String,
}

impl Ed25519Keypair {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let encoded_public_key = base64_encode(keypair.public.as_bytes());

        Self { inner: keypair, encoded_public_key }
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.inner.public
    }

    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }

    pub fn sign(&self, message: &str) -> String {
        let signature = self.inner.sign(message.as_bytes());
        base64_encode(signature.to_bytes())
    }
}

pub(super) struct Curve25519Keypair {
    secret_key: Curve25519SecretKey,
    public_key: Curve25519PublicKey,
    encoded_public_key: String,
}

const CURVE25519_PUBLIC_KEY_LEN: usize = 32;

impl Curve25519Keypair {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = Curve25519SecretKey::new(&mut rng);
        let public_key = Curve25519PublicKey::from(&secret_key);
        let encoded_public_key = base64_encode(public_key.as_bytes());

        Self { secret_key, public_key, encoded_public_key }
    }

    pub fn secret_key(&self) -> &Curve25519SecretKey {
        &self.secret_key
    }

    pub fn public_key(&self) -> &Curve25519PublicKey {
        &self.public_key
    }

    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct KeyId(pub(super) u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        base64_encode(value.0.to_le_bytes())
    }
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug, Zeroize)]
pub struct Curve25519PublicKey {
    pub(crate) inner: PublicKey,
}

impl Curve25519PublicKey {
    pub const KEY_LENGTH: usize = CURVE25519_PUBLIC_KEY_LEN;

    pub fn new(private_key: [u8; CURVE25519_PUBLIC_KEY_LEN]) -> Curve25519PublicKey {
        Self { inner: PublicKey::from(private_key) }
    }

    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; CURVE25519_PUBLIC_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Instantiate a Curve25519 public key from an unpadded base64
    /// representation.
    pub fn from_base64(base64_key: &str) -> Result<Curve25519PublicKey, Curve25519KeyError> {
        let key = base64_decode(base64_key)?;
        Self::from_slice(&key)
    }

    /// Try to create a `Curve25519PublicKey` from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Curve25519PublicKey, Curve25519KeyError> {
        let key_len = slice.len();

        if key_len == CURVE25519_PUBLIC_KEY_LEN {
            let mut key = [0u8; CURVE25519_PUBLIC_KEY_LEN];
            key.copy_from_slice(slice);

            Ok(Self::from(key))
        } else {
            Err(Curve25519KeyError::InvalidKeyLength(key_len))
        }
    }

    /// Serialize a Curve25519 public key to an unpadded base64 representation.
    pub fn to_base64(&self) -> String {
        base64_encode(self.inner.as_bytes())
    }
}

impl From<[u8; CURVE25519_PUBLIC_KEY_LEN]> for Curve25519PublicKey {
    fn from(bytes: [u8; CURVE25519_PUBLIC_KEY_LEN]) -> Curve25519PublicKey {
        Curve25519PublicKey { inner: PublicKey::from(bytes) }
    }
}

impl<'a> From<&'a Curve25519SecretKey> for Curve25519PublicKey {
    fn from(secret: &'a Curve25519SecretKey) -> Curve25519PublicKey {
        Curve25519PublicKey { inner: PublicKey::from(secret) }
    }
}

impl<'a> From<&'a EphemeralSecret> for Curve25519PublicKey {
    fn from(secret: &'a EphemeralSecret) -> Curve25519PublicKey {
        Curve25519PublicKey { inner: PublicKey::from(secret) }
    }
}

#[derive(Error, Debug, Clone)]
pub enum Curve25519KeyError {
    #[error("Failed decoding curve25519 key from base64: {}", .0)]
    Base64Error(#[from] DecodeError),
    #[error("Failed decoding curve25519 key from base64: \
             Invalid number of bytes for curve25519, expected {}, got {}.",
            CURVE25519_PUBLIC_KEY_LEN, .0)]
    InvalidKeyLength(usize),
}

#[cfg(test)]
mod tests {
    use super::{Curve25519KeyError, Curve25519PublicKey};
    use crate::utilities::DecodeError;

    #[test]
    fn decoding_invalid_base64_fails() {
        let base64_payload = "a";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(Curve25519KeyError::Base64Error(DecodeError::InvalidLength))
        ));

        let base64_payload = "a ";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(Curve25519KeyError::Base64Error(DecodeError::InvalidByte(..)))
        ));

        let base64_payload = "aZ";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(Curve25519KeyError::Base64Error(DecodeError::InvalidLastSymbol(..)))
        ));
    }

    #[test]
    fn decoding_incorrect_num_of_bytes_fails() {
        let base64_payload = "aaaa";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(Curve25519KeyError::InvalidKeyLength(..))
        ));
    }

    #[test]
    fn decoding_of_correct_num_of_bytes_succeeds() {
        let base64_payload = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        assert!(matches!(Curve25519PublicKey::from_base64(base64_payload), Ok(..)));
    }
}
