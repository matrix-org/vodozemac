// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, SignatureError};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    message::MegolmMessage,
    ratchet::{MegolmRatchetUnpicklingError, Ratchet, RatchetPickle},
    SessionKey, SESSION_KEY_VERSION,
};
use crate::{cipher::Cipher, utilities::base64_encode};

#[derive(Deserialize)]
#[serde(try_from = "GroupSessionPickle")]
pub struct GroupSession {
    ratchet: Ratchet,
    signing_key: ExpandedSecretKey,
    public_key: PublicKey,
}

impl Default for GroupSession {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupSession {
    pub fn new() -> Self {
        let mut rng = thread_rng();

        let secret_key = SecretKey::generate(&mut rng);
        let secret_key = ExpandedSecretKey::from(&secret_key);
        let public_key = PublicKey::from(&secret_key);

        Self { signing_key: secret_key, public_key, ratchet: Ratchet::new() }
    }

    pub fn session_id(&self) -> String {
        base64_encode(self.public_key.as_bytes())
    }

    pub fn message_index(&self) -> u32 {
        self.ratchet.index()
    }

    pub fn encrypt(&mut self, plaintext: &str) -> String {
        let cipher = Cipher::new_megolm(self.ratchet.as_bytes());

        let ciphertext = cipher.encrypt(plaintext.as_ref());
        let mut message = MegolmMessage::new(ciphertext, self.message_index());

        let mac = cipher.mac(message.bytes_for_mac());
        message.append_mac(mac);

        let signature = self.signing_key.sign(message.bytes_for_signing(), &self.public_key);
        message.append_signature(signature);

        self.ratchet.advance();

        base64_encode(message)
    }

    pub fn session_key(&self) -> SessionKey {
        let index = self.ratchet.index().to_be_bytes();

        let mut export: Vec<u8> = [
            [SESSION_KEY_VERSION].as_ref(),
            index.as_ref(),
            self.ratchet.as_bytes(),
            self.public_key.as_bytes(),
        ]
        .concat();

        let signature = self.signing_key.sign(&export, &self.public_key);
        export.extend(signature.to_bytes());

        let result = base64_encode(&export);
        export.zeroize();

        SessionKey(result)
    }

    pub fn pickle(&self) -> GroupSessionPickled {
        let pickle: GroupSessionPickle = self.to_pickle();
        GroupSessionPickled(
            serde_json::to_string_pretty(&pickle).expect("Group session serialization failed."),
        )
    }

    pub fn to_pickle(&self) -> GroupSessionPickle {
        GroupSessionPickle {
            ratchet: self.ratchet.clone().into(),
            signing_key: (&self.signing_key).into(),
            public_key: self.public_key.into(),
        }
    }

    pub fn unpickle(input: &str) -> Result<Self, GroupSessionUnpicklingError> {
        let pickle: GroupSessionPickle = serde_json::from_str(input)?;
        pickle.try_into()
    }
}

#[derive(Serialize, Deserialize)]
pub struct GroupSessionPickle {
    ratchet: RatchetPickle,
    signing_key: ExpandedSecretKeyPickle,
    public_key: PublicKeyPickle,
}

impl TryFrom<GroupSessionPickle> for GroupSession {
    type Error = GroupSessionUnpicklingError;

    fn try_from(pickle: GroupSessionPickle) -> Result<Self, Self::Error> {
        Ok(Self {
            ratchet: pickle.ratchet.try_into()?,
            signing_key: pickle.signing_key.try_into()?,
            public_key: pickle.public_key.try_into()?,
        })
    }
}

#[derive(Error, Debug)]
pub enum GroupSessionUnpicklingError {
    #[error("Invalid ratchet")]
    InvalidRatchet(#[from] MegolmRatchetUnpicklingError),
    #[error("Invalid signing key: {0}")]
    InvalidSigningKey(SignatureError),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(SignatureError),
    #[error("Pickle format corrupted: {0}")]
    CorruptedPickle(#[from] serde_json::error::Error),
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ExpandedSecretKeyPickle {
    key: Vec<u8>,
}

impl From<&ExpandedSecretKey> for ExpandedSecretKeyPickle {
    fn from(key: &ExpandedSecretKey) -> Self {
        Self { key: key.to_bytes().to_vec() }
    }
}

impl TryFrom<ExpandedSecretKeyPickle> for ExpandedSecretKey {
    type Error = GroupSessionUnpicklingError;

    fn try_from(pickle: ExpandedSecretKeyPickle) -> Result<Self, Self::Error> {
        ExpandedSecretKey::from_bytes(pickle.key.as_slice())
            .map_err(GroupSessionUnpicklingError::InvalidSigningKey)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKeyPickle {
    key: Vec<u8>,
}

impl From<PublicKey> for PublicKeyPickle {
    fn from(key: PublicKey) -> Self {
        Self { key: key.to_bytes().to_vec() }
    }
}

impl TryFrom<PublicKeyPickle> for PublicKey {
    type Error = GroupSessionUnpicklingError;

    fn try_from(pickle: PublicKeyPickle) -> Result<Self, Self::Error> {
        PublicKey::from_bytes(pickle.key.as_slice())
            .map_err(GroupSessionUnpicklingError::InvalidPublicKey)
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct GroupSessionPickled(String);

impl GroupSessionPickled {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
