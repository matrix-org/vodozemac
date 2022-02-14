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

use rand::thread_rng;
use serde::{Deserialize, Serialize};
pub use x25519_dalek::StaticSecret as Curve25519SecretKey;
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret};
use zeroize::Zeroize;

use super::KeyError;
use crate::utilities::{base64_decode, base64_encode};

#[derive(Serialize, Deserialize, Clone)]
#[serde(from = "Curve25519KeypairPickle")]
#[serde(into = "Curve25519KeypairPickle")]
pub(crate) struct Curve25519Keypair {
    pub secret_key: Curve25519SecretKey,
    pub public_key: Curve25519PublicKey,
    pub encoded_public_key: String,
}

const CURVE25519_SECRET_KEY_LEN: usize = 32;

impl Curve25519Keypair {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = Curve25519SecretKey::new(&mut rng);
        let public_key = Curve25519PublicKey::from(&secret_key);
        let encoded_public_key = base64_encode(public_key.as_bytes());

        Self { secret_key, public_key, encoded_public_key }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_secret_key(mut key: [u8; 32]) -> Self {
        let secret_key = Curve25519SecretKey::from(key);
        let public_key = Curve25519PublicKey::from(&secret_key);

        key.zeroize();

        Curve25519Keypair { secret_key, public_key, encoded_public_key: public_key.to_base64() }
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

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Curve25519PublicKey {
    pub(crate) inner: PublicKey,
}

#[cfg(feature = "libolm-compat")]
impl crate::utilities::Decode for Curve25519PublicKey {
    fn decode(
        reader: &mut impl std::io::Read,
    ) -> Result<Self, crate::utilities::LibolmDecodeError> {
        let key = <[u8; 32]>::decode(reader)?;

        Ok(Curve25519PublicKey::from(key))
    }
}

impl Curve25519PublicKey {
    pub const LENGTH: usize = 32;

    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.inner.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.inner.as_bytes()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: PublicKey::from(bytes) }
    }

    /// Instantiate a Curve25519 public key from an unpadded base64
    /// representation.
    pub fn from_base64(base64_key: &str) -> Result<Curve25519PublicKey, KeyError> {
        let key = base64_decode(base64_key)?;
        Self::from_slice(&key)
    }

    /// Try to create a `Curve25519PublicKey` from a slice of bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Curve25519PublicKey, KeyError> {
        let key_len = slice.len();

        if key_len == Self::LENGTH {
            let mut key = [0u8; Self::LENGTH];
            key.copy_from_slice(slice);

            Ok(Self::from(key))
        } else {
            Err(KeyError::InvalidKeyLength(key_len))
        }
    }

    /// Serialize a Curve25519 public key to an unpadded base64 representation.
    pub fn to_base64(&self) -> String {
        base64_encode(self.inner.as_bytes())
    }
}

impl From<[u8; Self::LENGTH]> for Curve25519PublicKey {
    fn from(bytes: [u8; Self::LENGTH]) -> Curve25519PublicKey {
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

impl<'a> From<&'a ReusableSecret> for Curve25519PublicKey {
    fn from(secret: &'a ReusableSecret) -> Curve25519PublicKey {
        Curve25519PublicKey { inner: PublicKey::from(secret) }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Curve25519KeypairPickle {
    secret: [u8; CURVE25519_SECRET_KEY_LEN],
    public: [u8; Curve25519PublicKey::LENGTH],
}

impl Drop for Curve25519KeypairPickle {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl From<Curve25519KeypairPickle> for Curve25519Keypair {
    fn from(pickle: Curve25519KeypairPickle) -> Self {
        Self {
            secret_key: pickle.secret.into(),
            public_key: pickle.public.into(),
            encoded_public_key: base64_encode(pickle.public),
        }
    }
}

impl From<Curve25519Keypair> for Curve25519KeypairPickle {
    fn from(key: Curve25519Keypair) -> Self {
        Curve25519KeypairPickle {
            secret: key.secret_key.to_bytes(),
            public: key.public_key.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Curve25519PublicKey;
    use crate::{utilities::DecodeError, KeyError};

    #[test]
    fn decoding_invalid_base64_fails() {
        let base64_payload = "a";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(KeyError::Base64Error(DecodeError::InvalidLength))
        ));

        let base64_payload = "a ";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(KeyError::Base64Error(DecodeError::InvalidByte(..)))
        ));

        let base64_payload = "aZ";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(KeyError::Base64Error(DecodeError::InvalidLastSymbol(..)))
        ));
    }

    #[test]
    fn decoding_incorrect_num_of_bytes_fails() {
        let base64_payload = "aaaa";
        assert!(matches!(
            Curve25519PublicKey::from_base64(base64_payload),
            Err(KeyError::InvalidKeyLength(..))
        ));
    }

    #[test]
    fn decoding_of_correct_num_of_bytes_succeeds() {
        let base64_payload = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA";
        assert!(matches!(Curve25519PublicKey::from_base64(base64_payload), Ok(..)));
    }
}
