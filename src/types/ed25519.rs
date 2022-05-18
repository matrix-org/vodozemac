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

use ed25519_dalek::{
    ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature, Verifier, PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::utilities::{base64_decode, base64_encode};

/// Error type describing signature verification failures.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// The signature wasn't valid base64.
    #[error("The signature couldn't be decoded: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The signature failed to be verified.
    #[error("The signature was invalid: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
}

/// A struct collecting both a public, and a secret, Ed25519 key.
#[derive(Deserialize, Serialize)]
#[serde(try_from = "Ed25519KeypairPickle")]
#[serde(into = "Ed25519KeypairPickle")]
pub struct Ed25519Keypair {
    secret_key: SecretKeys,
    public_key: Ed25519PublicKey,
}

impl Ed25519Keypair {
    /// Create a new, random, `Ed25519Keypair`.
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        Self { secret_key: keypair.secret.into(), public_key: Ed25519PublicKey(keypair.public) }
    }

    #[cfg(feature = "libolm-compat")]
    pub(crate) fn from_expanded_key(secret_key: &[u8; 64]) -> Result<Self, crate::KeyError> {
        let secret_key = ExpandedSecretKey::from_bytes(secret_key).map_err(SignatureError::from)?;
        let public_key = Ed25519PublicKey(PublicKey::from(&secret_key));

        Ok(Self { secret_key: secret_key.into(), public_key })
    }

    /// Get the public Ed25519 key of this keypair.
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    /// Sign the given message with our secret key.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.secret_key.sign(message, &self.public_key())
    }
}

impl Default for Ed25519Keypair {
    fn default() -> Self {
        Self::new()
    }
}

/// An Ed25519 secret key, used to create digital signatures.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct Ed25519SecretKey(Box<SecretKey>);

impl Ed25519SecretKey {
    /// Create a new random `Ed25519SecretKey`.
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let key = Box::new(SecretKey::generate(&mut rng));

        Self(key)
    }

    /// Get the byte representation of the secret key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Try to create a `Ed25519SecretKey` from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, crate::KeyError> {
        let key = Box::new(SecretKey::from_bytes(bytes).map_err(SignatureError::from)?);

        Ok(Self(key))
    }

    /// Convert the secret key to a base64 encoded string.
    ///
    /// This can be useful if the secret key needs to be sent over the network
    /// or persisted.
    ///
    /// **Warning**: The string should be zeroized after it has been used,
    /// otherwise an unintentional copy of the key might exist in memory.
    pub fn to_base64(&self) -> String {
        base64_encode(self.as_bytes())
    }

    /// Try to create a `Ed25519SecretKey` from a base64 encoded string.
    pub fn from_base64(key: &str) -> Result<Self, crate::KeyError> {
        let mut bytes = base64_decode(key)?;
        let key = Self::from_slice(&bytes);

        bytes.zeroize();

        key
    }

    /// Get the public key that matches this `Ed25519SecretKey`.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(PublicKey::from(self.0.as_ref()))
    }

    /// Sign the given slice of bytes with this `Ed25519SecretKey`.
    ///
    /// The signature can be verified using the public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use vodozemac::{Ed25519SecretKey, Ed25519PublicKey};
    ///
    /// let secret = Ed25519SecretKey::new();
    /// let message = "It's dangerous to go alone";
    ///
    /// let signature = secret.sign(message.as_bytes());
    ///
    /// let public_key = secret.public_key();
    ///
    /// public_key.verify(message.as_bytes(), &signature).expect("The signature has to be valid");
    /// ```
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let expanded = ExpandedSecretKey::from(self.0.as_ref());
        Ed25519Signature(expanded.sign(message, &self.public_key().0))
    }
}

impl Default for Ed25519SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
enum SecretKeys {
    Normal(Box<SecretKey>),
    Expanded(Box<ExpandedSecretKey>),
}

impl SecretKeys {
    fn public_key(&self) -> Ed25519PublicKey {
        match &self {
            SecretKeys::Normal(k) => Ed25519PublicKey(PublicKey::from(k.as_ref())),
            SecretKeys::Expanded(k) => Ed25519PublicKey(PublicKey::from(k.as_ref())),
        }
    }

    fn sign(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Ed25519Signature {
        let signature = match &self {
            SecretKeys::Normal(k) => {
                let expanded = ExpandedSecretKey::from(k.as_ref());
                expanded.sign(message.as_ref(), &public_key.0)
            }
            SecretKeys::Expanded(k) => k.sign(message.as_ref(), &public_key.0),
        };

        Ed25519Signature(signature)
    }
}

/// An Ed25519 public key, used to verify digital signatures.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(transparent)]
pub struct Ed25519PublicKey(PublicKey);

impl Ed25519PublicKey {
    /// The number of bytes a Ed25519 public key has.
    pub const LENGTH: usize = PUBLIC_KEY_LENGTH;

    /// Try to create a `Ed25519PublicKey` from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, crate::KeyError> {
        Ok(Self(PublicKey::from_bytes(bytes).map_err(SignatureError::from)?))
    }

    /// View this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }

    /// Instantiate a Ed25519PublicKey public key from an unpadded base64
    /// representation.
    pub fn from_base64(base64_key: &str) -> Result<Self, crate::KeyError> {
        let key = base64_decode(base64_key)?;
        Self::from_slice(&key)
    }

    /// Serialize a Ed25519PublicKey public key to an unpadded base64
    /// representation.
    pub fn to_base64(&self) -> String {
        base64_encode(self.as_bytes())
    }

    /// Verify that the provided signature for a given message has been signed
    /// by the private key matching this public one.
    ///
    /// By default this performs an [RFC8032] compatible signature check. A
    /// stricter version of the signature check can be enabled with the
    /// `strict-signatures` feature flag.
    ///
    /// The stricter variant is compatible with libsodium 0.16 and under the
    /// hood uses the [`ed25519_dalek::PublicKey::verify_strict()`] method.
    ///
    /// For more info, see the ed25519_dalek [README] and [this] post.
    ///
    /// [RFC8032]: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.7
    /// [README]: https://github.com/dalek-cryptography/ed25519-dalek#a-note-on-signature-malleability
    /// [this]: https://hdevalence.ca/blog/2020-10-04-its-25519am
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), SignatureError> {
        if cfg!(feature = "strict-signatures") {
            Ok(self.0.verify_strict(message, &signature.0)?)
        } else {
            Ok(self.0.verify(message, &signature.0)?)
        }
    }
}

impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PublicKey({})", self.to_base64())
    }
}

/// An Ed25519 digital signature, can be used to verify the authenticity of a
/// message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature(pub(crate) Signature);

impl Ed25519Signature {
    /// The number of bytes a Ed25519 signature has.
    pub const LENGTH: usize = SIGNATURE_LENGTH;

    /// Try to create a `Ed25519Signature` from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(Signature::try_from(bytes)?))
    }

    /// Try to create a `Ed25519Signature` from an unpadded base64
    /// representation.
    pub fn from_base64(signature: &str) -> Result<Self, SignatureError> {
        Ok(Self(Signature::try_from(base64_decode(signature)?.as_slice())?))
    }

    /// Serialize an `Ed25519Signature` to an unpadded base64 representation.
    pub fn to_base64(&self) -> String {
        base64_encode(self.0.to_bytes())
    }

    /// Convert the `Ed25519Signature` to a byte array.
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }
}

impl Clone for Ed25519Keypair {
    fn clone(&self) -> Self {
        let secret_key: Result<SecretKeys, _> = match &self.secret_key {
            SecretKeys::Normal(k) => SecretKey::from_bytes(k.as_bytes()).map(|k| k.into()),
            SecretKeys::Expanded(k) => {
                let mut bytes = k.to_bytes();
                let key = ExpandedSecretKey::from_bytes(&bytes).map(|k| k.into());
                bytes.zeroize();

                key
            }
        };

        Self {
            secret_key: secret_key.expect("Couldn't create a secret key copy."),
            public_key: self.public_key,
        }
    }
}

impl From<Ed25519Keypair> for Ed25519KeypairPickle {
    fn from(key: Ed25519Keypair) -> Self {
        Self(key.secret_key)
    }
}

impl From<SecretKey> for SecretKeys {
    fn from(key: SecretKey) -> Self {
        Self::Normal(Box::new(key))
    }
}

impl From<ExpandedSecretKey> for SecretKeys {
    fn from(key: ExpandedSecretKey) -> Self {
        Self::Expanded(Box::new(key))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519KeypairPickle(SecretKeys);

impl From<Ed25519KeypairPickle> for Ed25519Keypair {
    fn from(pickle: Ed25519KeypairPickle) -> Self {
        let secret_key = pickle.0;
        let public_key = secret_key.public_key();

        Self { secret_key, public_key }
    }
}
