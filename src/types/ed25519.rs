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

pub use ed25519_dalek::SignatureError;
use ed25519_dalek::{
    ExpandedSecretKey, Keypair, PublicKey, SecretKey, Signature, Verifier, PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::utilities::base64_encode;

#[derive(Deserialize, Serialize)]
#[serde(try_from = "Ed25519KeypairPickle")]
#[serde(into = "Ed25519KeypairPickle")]
pub struct Ed25519Keypair {
    secret_key: Ed25519SecretKey,
    public_key: Ed25519PublicKey,
    encoded_public_key: String,
}

impl Ed25519Keypair {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let encoded_public_key = base64_encode(keypair.public.as_bytes());

        Self {
            secret_key: keypair.secret.into(),
            public_key: Ed25519PublicKey(keypair.public),
            encoded_public_key,
        }
    }

    pub fn from_expanded_key(secret_key: &[u8; 64]) -> Result<Self, SignatureError> {
        let secret_key = ExpandedSecretKey::from_bytes(secret_key)?;
        let public_key = Ed25519PublicKey(PublicKey::from(&secret_key));
        let encoded_public_key = base64_encode(public_key.as_bytes());

        Ok(Self { secret_key: secret_key.into(), public_key, encoded_public_key })
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }

    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.secret_key.sign(message, self.public_key())
    }
}

#[derive(Serialize, Deserialize)]
enum Ed25519SecretKey {
    Normal(SecretKey),
    Expanded(ExpandedSecretKey),
}

impl Ed25519SecretKey {
    fn public_key(&self) -> Ed25519PublicKey {
        match &self {
            Ed25519SecretKey::Normal(k) => Ed25519PublicKey(PublicKey::from(k)),
            Ed25519SecretKey::Expanded(k) => Ed25519PublicKey(PublicKey::from(k)),
        }
    }

    fn sign(&self, message: &[u8], public_key: &Ed25519PublicKey) -> Ed25519Signature {
        let signature = match &self {
            Ed25519SecretKey::Normal(k) => {
                let expanded = ExpandedSecretKey::from(k);
                expanded.sign(message.as_ref(), &public_key.0)
            }
            Ed25519SecretKey::Expanded(k) => k.sign(message.as_ref(), &public_key.0),
        };

        Ed25519Signature(signature)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(transparent)]
pub struct Ed25519PublicKey(PublicKey);

impl Ed25519PublicKey {
    pub const LENGTH: usize = PUBLIC_KEY_LENGTH;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(PublicKey::from_bytes(bytes)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

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
            self.0.verify_strict(message, &signature.0)
        } else {
            self.0.verify(message, &signature.0)
        }
    }
}

pub struct Ed25519Signature(pub(crate) Signature);

impl Ed25519Signature {
    pub const LENGTH: usize = SIGNATURE_LENGTH;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(Signature::from_bytes(bytes)?))
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.0.to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }
}

impl Clone for Ed25519Keypair {
    fn clone(&self) -> Self {
        let secret_key: Result<Ed25519SecretKey, _> = match &self.secret_key {
            Ed25519SecretKey::Normal(k) => SecretKey::from_bytes(k.as_bytes()).map(|k| k.into()),
            Ed25519SecretKey::Expanded(k) => {
                let mut bytes = k.to_bytes();
                let key = ExpandedSecretKey::from_bytes(&bytes).map(|k| k.into());
                bytes.zeroize();

                key
            }
        };

        Self {
            secret_key: secret_key.expect("Couldn't create a secret key copy."),
            public_key: self.public_key,
            encoded_public_key: self.encoded_public_key.clone(),
        }
    }
}

impl From<Ed25519Keypair> for Ed25519KeypairPickle {
    fn from(key: Ed25519Keypair) -> Self {
        Self(key.secret_key)
    }
}

impl From<SecretKey> for Ed25519SecretKey {
    fn from(key: SecretKey) -> Self {
        Self::Normal(key)
    }
}

impl From<ExpandedSecretKey> for Ed25519SecretKey {
    fn from(key: ExpandedSecretKey) -> Self {
        Self::Expanded(key)
    }
}

#[derive(Error, Debug)]
#[error("Invalid Ed25519 keypair pickle: {0}")]
pub struct Ed25519KeypairUnpicklingError(#[from] SignatureError);

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519KeypairPickle(Ed25519SecretKey);

impl TryFrom<Ed25519KeypairPickle> for Ed25519Keypair {
    type Error = Ed25519KeypairUnpicklingError;

    fn try_from(pickle: Ed25519KeypairPickle) -> Result<Self, Self::Error> {
        let secret_key = pickle.0;
        let public_key = secret_key.public_key();

        Ok(Self { secret_key, public_key, encoded_public_key: public_key.to_base64() })
    }
}
