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

pub use ed25519_dalek::PublicKey as Ed25519PublicKey;
use ed25519_dalek::{
    ExpandedSecretKey as ExpandedEd25519SecretKey, Keypair,
    SecretKey as UnexpandedEd25519SecretKey, SignatureError,
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

        Self { secret_key: keypair.secret.into(), public_key: keypair.public, encoded_public_key }
    }

    pub fn from_expanded_key(secret_key: &[u8; 64]) -> Result<Self, SignatureError> {
        let secret_key = ExpandedEd25519SecretKey::from_bytes(secret_key)?;
        let public_key = Ed25519PublicKey::from(&secret_key);
        let encoded_public_key = base64_encode(public_key.as_bytes());

        Ok(Self { secret_key: secret_key.into(), public_key, encoded_public_key })
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }

    pub fn sign(&self, message: &str) -> String {
        self.secret_key.sign(message, self.public_key())
    }
}

enum Ed25519SecretKey {
    Normal(UnexpandedEd25519SecretKey),
    Expanded(ExpandedEd25519SecretKey),
}

impl Ed25519SecretKey {
    fn public_key(&self) -> Ed25519PublicKey {
        match &self {
            Ed25519SecretKey::Normal(k) => Ed25519PublicKey::from(k),
            Ed25519SecretKey::Expanded(k) => Ed25519PublicKey::from(k),
        }
    }

    fn sign(&self, message: &str, public_key: &Ed25519PublicKey) -> String {
        let signature = match &self {
            Ed25519SecretKey::Normal(k) => {
                let expanded = ExpandedEd25519SecretKey::from(k);
                expanded.sign(message.as_ref(), public_key)
            }
            Ed25519SecretKey::Expanded(k) => k.sign(message.as_ref(), public_key),
        };

        base64_encode(signature.to_bytes())
    }
}

impl Clone for Ed25519Keypair {
    fn clone(&self) -> Self {
        let secret_key: Result<Ed25519SecretKey, _> = match &self.secret_key {
            Ed25519SecretKey::Normal(k) => {
                UnexpandedEd25519SecretKey::from_bytes(k.as_bytes()).map(|k| k.into())
            }
            Ed25519SecretKey::Expanded(k) => {
                let mut bytes = k.to_bytes();
                let key = ExpandedEd25519SecretKey::from_bytes(&bytes).map(|k| k.into());
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
        match key.secret_key {
            Ed25519SecretKey::Normal(k) => Ed25519KeypairPickle::Normal(k.as_bytes().to_vec()),
            Ed25519SecretKey::Expanded(k) => Ed25519KeypairPickle::Expanded(k.to_bytes().to_vec()),
        }
    }
}

impl From<UnexpandedEd25519SecretKey> for Ed25519SecretKey {
    fn from(key: UnexpandedEd25519SecretKey) -> Self {
        Self::Normal(key)
    }
}

impl From<ExpandedEd25519SecretKey> for Ed25519SecretKey {
    fn from(key: ExpandedEd25519SecretKey) -> Self {
        Self::Expanded(key)
    }
}

#[derive(Error, Debug)]
#[error("Invalid Ed25519 keypair pickle: {0}")]
pub struct Ed25519KeypairUnpicklingError(#[from] SignatureError);

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub enum Ed25519KeypairPickle {
    Normal(Vec<u8>),
    Expanded(Vec<u8>),
}

impl TryFrom<Ed25519KeypairPickle> for Ed25519Keypair {
    type Error = Ed25519KeypairUnpicklingError;

    fn try_from(pickle: Ed25519KeypairPickle) -> Result<Self, Self::Error> {
        let secret_key: Ed25519SecretKey = match &pickle {
            Ed25519KeypairPickle::Normal(k) => UnexpandedEd25519SecretKey::from_bytes(k)?.into(),
            Ed25519KeypairPickle::Expanded(k) => ExpandedEd25519SecretKey::from_bytes(k)?.into(),
        };

        let public_key = secret_key.public_key();

        Ok(Self { secret_key, public_key, encoded_public_key: base64_encode(public_key) })
    }
}
