// Copyright 2024 Damir Jelić
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

#![allow(dead_code)]

use base64::decoded_len_estimate;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{base64_decode, base64_encode, KeyError};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KyberSharedSecret {
    inner: Box<pqc_kyber::SharedSecret>,
}

impl KyberSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberCipherText {
    inner: [u8; pqc_kyber::KYBER_CIPHERTEXTBYTES],
}

pub struct EncapsulationResult {
    pub(crate) shared_secret: KyberSharedSecret,
    pub(crate) ciphertext: KyberCipherText,
}

#[derive(Clone, PartialEq, Eq)]
pub struct KyberPublicKey {
    inner: Box<pqc_kyber::PublicKey>,
}

impl Serialize for KyberPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

impl<'de> Deserialize<'de> for KyberPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}

impl std::fmt::Debug for KyberPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl KyberPublicKey {
    /// The number of bytes a Kyber public key has.
    pub const LENGTH: usize = pqc_kyber::KYBER_PUBLICKEYBYTES;

    const BASE64_LENGTH: usize = 2091;
    const PADDED_BASE64_LENGTH: usize = Self::BASE64_LENGTH + 1;

    pub fn encapsulate(&self) -> EncapsulationResult {
        let mut rng = thread_rng();
        let mut shared_secret =
            KyberSharedSecret { inner: Box::new([0u8; pqc_kyber::KYBER_SSBYTES]) };

        // TODO: remove this unwrap
        let mut result = pqc_kyber::encapsulate(self.inner.as_slice(), &mut rng).unwrap();

        shared_secret.inner.copy_from_slice(&result.1);
        let ciphertext = KyberCipherText { inner: result.0 };

        result.zeroize();

        EncapsulationResult { shared_secret, ciphertext }
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.inner.as_slice())
    }

    pub fn fingerprint(&self) -> String {
        let sha = Sha256::new();
        let digest = sha.chain_update(self.inner.as_slice()).finalize();

        base64_encode(digest)
    }

    pub fn from_base64(input: &str) -> Result<Self, KeyError> {
        if input.len() != Self::BASE64_LENGTH && input.len() != Self::PADDED_BASE64_LENGTH {
            Err(crate::KeyError::InvalidKeyLength {
                key_type: "Kyber1024",
                expected_length: Self::LENGTH,
                length: decoded_len_estimate(input.len()),
            })
        } else {
            let mut bytes = base64_decode(input)?;
            let mut key_bytes = [0u8; Self::LENGTH];

            key_bytes.copy_from_slice(&bytes);
            let key = Self::from_bytes(&key_bytes);

            bytes.zeroize();
            key_bytes.zeroize();

            Ok(key)
        }
    }

    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.inner
    }

    pub fn from_bytes(slice: &[u8; Self::LENGTH]) -> Self {
        // TODO: Can we just take any random bytes or does a public key need to
        // contain some structure?
        let mut public_key = Box::new([0u8; Self::LENGTH]);

        public_key.copy_from_slice(slice);

        Self { inner: public_key }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey {
    inner: Box<pqc_kyber::SecretKey>,
}

impl KyberSecretKey {
    pub fn new() -> Self {
        let KyberKeyPair { secret_key, .. } = KyberKeyPair::new();

        secret_key
    }

    pub fn decapsulate(&self, ciphertext: &KyberCipherText) -> Result<KyberSharedSecret, ()> {
        let mut shared_secret = Box::new([0u8; pqc_kyber::KYBER_SSBYTES]);

        // TODO: remove this unwrap
        let mut result = pqc_kyber::decapsulate(&ciphertext.inner, self.inner.as_slice()).unwrap();
        shared_secret.copy_from_slice(&result);

        result.zeroize();

        Ok(KyberSharedSecret { inner: shared_secret })
    }

    pub fn public_key(&self) -> KyberPublicKey {
        let public_key = pqc_kyber::public(self.inner.as_slice());

        KyberPublicKey { inner: Box::new(public_key) }
    }

    pub fn fingerprint(&self) -> String {
        let sha = Sha256::new();
        let public_key = self.public_key();
        let digest = sha.chain_update(public_key.inner.as_slice()).finalize();

        base64_encode(digest)
    }
}

pub struct KyberKeyPair {
    pub(crate) secret_key: KyberSecretKey,
    pub(crate) public_key: KyberPublicKey,
}

impl KyberKeyPair {
    pub fn new() -> Self {
        let mut rng = thread_rng();

        let mut public_key =
            KyberPublicKey { inner: Box::new([0; pqc_kyber::KYBER_PUBLICKEYBYTES]) };
        let mut secret_key =
            KyberSecretKey { inner: Box::new([0; pqc_kyber::KYBER_SECRETKEYBYTES]) };

        // This only fails if the RNG fails.
        let mut keypair = pqc_kyber::keypair(&mut rng).expect(
            "We should be always able to generate enough random bytes for a Kyber keypair.",
        );

        public_key.inner.copy_from_slice(&keypair.public);
        secret_key.inner.copy_from_slice(&keypair.secret);

        keypair.secret.zeroize();

        Self { secret_key, public_key }
    }

    pub fn public_key(&self) -> &KyberPublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encapsulation_roundtrip() {
        let alice = KyberKeyPair::new();

        let result = alice.public_key().encapsulate();

        let shared_secret = alice.secret_key.decapsulate(&result.ciphertext).unwrap();

        assert_eq!(shared_secret.inner, result.shared_secret.inner);
    }

    #[test]
    fn base64_encoding() {
        let alice = KyberKeyPair::new();

        let encoded = alice.public_key().to_base64();
        let decoded = KyberPublicKey::from_base64(&encoded)
            .expect("We should be able to decode a Kyber public key");

        assert_eq!(alice.public_key(), &decoded);
    }
}
