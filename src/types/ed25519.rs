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

use base64::decoded_len_estimate;
use base64ct::Encoding;
use curve25519_dalek::EdwardsPoint;
#[cfg(not(fuzzing))]
use ed25519_dalek::Verifier;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::thread_rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::{ByteBuf as SerdeByteBuf, Bytes as SerdeBytes};
use sha2::Sha512;
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

struct ExpandedSecretKey {
    source: Box<[u8; 64]>,
    inner: Box<ed25519_dalek::hazmat::ExpandedSecretKey>,
}

impl ExpandedSecretKey {
    fn from_bytes(bytes: &[u8; 64]) -> Result<Self, ed25519_dalek::SignatureError> {
        let mut source = Box::new([0u8; 64]);
        source.copy_from_slice(bytes);

        Ok(Self {
            source,
            inner: ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(bytes).into(),
        })
    }

    fn as_bytes(&self) -> &[u8; 64] {
        &self.source
    }

    fn sign(&self, message: &[u8]) -> Signature {
        ed25519_dalek::hazmat::raw_sign::<Sha512>(&self.inner, message, &self.public_key().0)
    }

    fn public_key(&self) -> Ed25519PublicKey {
        let point = EdwardsPoint::mul_base(&self.inner.scalar);
        Ed25519PublicKey(VerifyingKey::from(point))
    }
}

impl Clone for ExpandedSecretKey {
    fn clone(&self) -> Self {
        let source = self.source.clone();
        Self {
            source,
            inner: ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&self.source).into(),
        }
    }
}

impl Serialize for ExpandedSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_bytes();
        SerdeBytes::new(bytes).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for ExpandedSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let mut bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        let length = bytes.len();

        if bytes.len() != 64 {
            bytes.zeroize();

            Err(serde::de::Error::custom(format!(
                "Invalid secret key length: expected 64 bytes, got {length}"
            )))
        } else {
            let mut slice = [0u8; 64];
            slice.copy_from_slice(&bytes);

            let ret = ExpandedSecretKey::from_bytes(&slice);

            slice.zeroize();
            bytes.zeroize();

            ret.map_err(serde::de::Error::custom)
        }
    }
}

impl Ed25519Keypair {
    /// Create a new, random, `Ed25519Keypair`.
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        Self {
            public_key: Ed25519PublicKey(signing_key.verifying_key()),
            secret_key: signing_key.into(),
        }
    }

    #[cfg(feature = "libolm-compat")]
    pub(crate) fn from_expanded_key(secret_key: &[u8; 64]) -> Result<Self, crate::KeyError> {
        let secret_key = ExpandedSecretKey::from_bytes(secret_key).map_err(SignatureError::from)?;
        let public_key = secret_key.public_key();

        Ok(Self { secret_key: secret_key.into(), public_key })
    }

    #[cfg(feature = "libolm-compat")]
    pub(crate) fn expanded_secret_key(&self) -> Box<[u8; 64]> {
        use sha2::Digest;

        let mut expanded = Box::new([0u8; 64]);

        match &self.secret_key {
            SecretKeys::Normal(k) => {
                let mut k = k.to_bytes();
                Sha512::new().chain_update(k).finalize_into(expanded.as_mut_slice().into());
                k.zeroize();
            }
            SecretKeys::Expanded(k) => expanded.copy_from_slice(k.as_bytes()),
        }

        expanded
    }

    /// Get the public Ed25519 key of this keypair.
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.public_key
    }

    /// Sign the given message with our secret key.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.secret_key.sign(message)
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
pub struct Ed25519SecretKey(Box<SigningKey>);

impl Ed25519SecretKey {
    /// The number of bytes a Ed25519 secret key has.
    pub const LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;

    const BASE64_LENGTH: usize = 43;
    const PADDED_BASE64_LENGTH: usize = 44;

    /// Create a new random `Ed25519SecretKey`.
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let key = Box::new(signing_key);

        Self(key)
    }

    /// Get the byte representation of the secret key.
    ///
    /// **Warning**: This creates a copy of the key which won't be zeroized, the
    /// caller of the method needs to make sure to zeroize the returned array.
    pub fn to_bytes(&self) -> Box<[u8; 32]> {
        Box::new(self.0.to_bytes())
    }

    /// Try to create a `Ed25519SecretKey` from a slice of bytes.
    pub fn from_slice(bytes: &[u8; 32]) -> Self {
        Self(Box::new(SigningKey::from_bytes(bytes)))
    }

    /// Convert the secret key to a base64 encoded string.
    ///
    /// This can be useful if the secret key needs to be sent over the network
    /// or persisted.
    ///
    /// **Warning**: The string should be zeroized after it has been used,
    /// otherwise an unintentional copy of the key might exist in memory.
    pub fn to_base64(&self) -> String {
        let mut bytes = self.to_bytes();
        let ret = base64ct::Base64Unpadded::encode_string(bytes.as_ref());

        bytes.zeroize();

        ret
    }

    /// Try to create a `Ed25519SecretKey` from a base64 encoded string.
    pub fn from_base64(input: &str) -> Result<Self, crate::KeyError> {
        if input.len() != Self::BASE64_LENGTH && input.len() != Self::PADDED_BASE64_LENGTH {
            Err(crate::KeyError::InvalidKeyLength {
                key_type: "Ed25519",
                expected_length: ed25519_dalek::SECRET_KEY_LENGTH,
                length: decoded_len_estimate(input.len()),
            })
        } else {
            // Ed25519 secret keys can sometimes be encoded with padding, don't ask me why.
            // This means that if the unpadded decoding fails, we have to attempt the padded
            // one.
            let mut bytes = if let Ok(bytes) = base64ct::Base64Unpadded::decode_vec(input) {
                bytes
            } else {
                base64ct::Base64::decode_vec(input)?
            };

            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let key = Self::from_slice(&key_bytes);

            bytes.zeroize();
            key_bytes.zeroize();

            Ok(key)
        }
    }

    /// Get the public key that matches this `Ed25519SecretKey`.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key())
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
        Ed25519Signature(self.0.sign(message))
    }
}

impl Default for Ed25519SecretKey {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
enum SecretKeys {
    Normal(Box<SigningKey>),
    Expanded(Box<ExpandedSecretKey>),
}

impl SecretKeys {
    fn public_key(&self) -> Ed25519PublicKey {
        match &self {
            SecretKeys::Normal(k) => Ed25519PublicKey(k.verifying_key()),
            SecretKeys::Expanded(k) => k.public_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signature = match &self {
            SecretKeys::Normal(k) => k.sign(message),
            SecretKeys::Expanded(k) => k.sign(message),
        };

        Ed25519Signature(signature)
    }
}

/// An Ed25519 public key, used to verify digital signatures.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(transparent)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Ed25519PublicKey {
    /// The number of bytes a Ed25519 public key has.
    pub const LENGTH: usize = PUBLIC_KEY_LENGTH;

    const BASE64_LENGTH: usize = 43;
    const PADDED_BASE64_LENGTH: usize = 44;

    /// Try to create a `Ed25519PublicKey` from a slice of bytes.
    pub fn from_slice(bytes: &[u8; 32]) -> Result<Self, crate::KeyError> {
        Ok(Self(VerifyingKey::from_bytes(bytes).map_err(SignatureError::from)?))
    }

    /// View this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.as_bytes()
    }

    /// Instantiate a Ed25519PublicKey public key from an unpadded base64
    /// representation.
    pub fn from_base64(input: &str) -> Result<Self, crate::KeyError> {
        if input.len() != Self::BASE64_LENGTH && input.len() != Self::PADDED_BASE64_LENGTH {
            Err(crate::KeyError::InvalidKeyLength {
                key_type: "Ed25519",
                expected_length: Self::LENGTH,
                length: decoded_len_estimate(input.len()),
            })
        } else {
            let mut bytes = base64_decode(input)?;
            let mut key_bytes = [0u8; 32];

            key_bytes.copy_from_slice(&bytes);
            let key = Self::from_slice(&key_bytes);

            bytes.zeroize();
            key_bytes.zeroize();

            key
        }
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
    #[cfg(not(fuzzing))]
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

    #[cfg(fuzzing)]
    pub fn verify(
        &self,
        _message: &[u8],
        _signature: &Ed25519Signature,
    ) -> Result<(), SignatureError> {
        Ok(())
    }
}

impl Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("ed25519:{self}");
        <str as std::fmt::Debug>::fmt(&s, f)
    }
}

/// An Ed25519 digital signature, can be used to verify the authenticity of a
/// message.
#[derive(Clone, Copy, PartialEq, Eq)]
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

impl Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("ed25519:{self}");
        <str as std::fmt::Debug>::fmt(&s, f)
    }
}

impl Clone for Ed25519Keypair {
    fn clone(&self) -> Self {
        let secret_key: SecretKeys = match &self.secret_key {
            SecretKeys::Normal(k) => SecretKeys::Normal(k.clone()),
            SecretKeys::Expanded(k) => SecretKeys::Expanded(k.clone()),
        };

        Self { secret_key, public_key: self.public_key }
    }
}

impl From<Ed25519Keypair> for Ed25519KeypairPickle {
    fn from(key: Ed25519Keypair) -> Self {
        Self(key.secret_key)
    }
}

impl From<SigningKey> for SecretKeys {
    fn from(key: SigningKey) -> Self {
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

#[cfg(test)]
mod tests {
    use super::ExpandedSecretKey;
    use crate::{
        types::ed25519::SecretKeys, Ed25519Keypair, Ed25519PublicKey, Ed25519SecretKey, KeyError,
    };

    #[test]
    fn byte_decoding_roundtrip_succeeds_for_secret_key() {
        let bytes = *b"oooooooooooooooooooooooooooooooo";
        let key = Ed25519SecretKey::from_slice(&bytes);
        assert_eq!(*(key.to_bytes()), bytes);
    }

    #[test]
    fn base64_decoding_incorrect_num_of_bytes_fails_for_secret_key() {
        assert!(matches!(
            Ed25519SecretKey::from_base64("foo"),
            Err(KeyError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn unpadded_base64_decoding_roundtrip_succeeds_for_secret_key() {
        let base64 = "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE";
        let key = Ed25519SecretKey::from_base64(base64).expect("Should decode key from base64");
        assert_eq!(key.to_base64(), base64);
    }

    #[test]
    fn padded_base64_decoding_roundtrip_succeeds_for_secret_key() {
        let base64 = "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=";
        let key = Ed25519SecretKey::from_base64(base64).expect("Should decode key from base64");
        assert_eq!(key.to_base64(), base64.trim_end_matches('='));
    }

    #[test]
    fn byte_decoding_roundtrip_succeeds_for_public_key() {
        let bytes = *b"oooooooooooooooooooooooooooooooo";
        let key = Ed25519PublicKey::from_slice(&bytes).expect("Should decode key from bytes");
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn base64_decoding_incorrect_num_of_bytes_fails_for_public_key() {
        assert!(matches!(
            Ed25519PublicKey::from_base64("foo"),
            Err(KeyError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn unpadded_base64_decoding_roundtrip_succeeds_for_public_key() {
        let base64 = "b29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb28";
        let key = Ed25519PublicKey::from_base64(base64).expect("Should decode key from base64");
        assert_eq!(key.to_base64(), base64);
    }

    #[test]
    fn padded_base64_decoding_roundtrip_succeeds_for_public_key() {
        let base64 = "b29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb28=";
        let key = Ed25519PublicKey::from_base64(base64).expect("Should decode key from base64");
        assert_eq!(key.to_base64(), base64.trim_end_matches('='));
    }

    #[test]
    fn verifying_valid_signature_succeeds() {
        let key_pair = Ed25519Keypair::new();
        let signature = key_pair.secret_key.sign(b"foo");
        key_pair.public_key().verify(b"foo", &signature).expect("Should verify valid signature");
    }

    #[test]
    fn verifying_invalid_signature_fails() {
        let key_pair = Ed25519Keypair::new();
        let signature = key_pair.secret_key.sign(b"foo");
        key_pair
            .public_key()
            .verify(b"bar", &signature)
            .expect_err("Should reject invalid signature");
    }

    #[test]
    fn can_only_expand_secret_key_once() {
        let key_pair = Ed25519Keypair::new();
        assert!(matches!(key_pair.secret_key, SecretKeys::Normal(_)));

        let expanded_key = key_pair.expanded_secret_key();
        let expanded_key_pair = Ed25519Keypair::from_expanded_key(&expanded_key).unwrap();
        assert!(matches!(expanded_key_pair.secret_key, SecretKeys::Expanded(_)));
        assert_eq!(expanded_key_pair.public_key(), key_pair.public_key());

        let reexpanded_key = expanded_key_pair.expanded_secret_key();
        assert_eq!(reexpanded_key, expanded_key);
    }

    #[test]
    fn serialization_roundtrip_succeeds() {
        let bytes = b"9999999999999999999999999999999999999999999999999999999999999999";
        let key = ExpandedSecretKey::from_bytes(bytes).unwrap();
        let serialized = serde_json::to_value(key).expect("Should serialize key");
        let deserialized = serde_json::from_value::<ExpandedSecretKey>(serialized)
            .expect("Should deserialize key");
        assert_eq!(deserialized.as_bytes(), bytes);
    }

    #[test]
    fn deserializing_from_invalid_length_fails() {
        let serialized = serde_json::to_value(b"foo").expect("Should serialize key");
        let deserialized = serde_json::from_value::<ExpandedSecretKey>(serialized);
        assert!(deserialized.is_err());
    }
}
