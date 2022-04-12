// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::ratchet::Ratchet;
use crate::{
    utilities::{base64_decode, base64_encode},
    Ed25519PublicKey, Ed25519Signature, SignatureError,
};

#[derive(Debug, Error)]
pub enum SessionKeyDecodeError {
    #[error("The session had a invalid version, expected {0}, got {1}")]
    Version(u8, u8),
    #[error("The session key was too short {0}")]
    Read(#[from] std::io::Error),
    #[error("The session key wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("The signature on the session key was invalid: {0}")]
    Signature(#[from] SignatureError),
    #[error("The public key of session was invalid: {0}")]
    PublicKey(#[from] crate::KeyError),
}

pub struct ExportedSessionKey {
    pub(crate) ratchet_index: u32,
    pub(crate) ratchet: Box<[u8; 128]>,
    pub(crate) signing_key: Ed25519PublicKey,
}

pub struct SessionKey {
    pub(super) session_key: ExportedSessionKey,
    pub(super) signature: Ed25519Signature,
}

impl Zeroize for ExportedSessionKey {
    fn zeroize(&mut self) {
        self.ratchet_index.zeroize();
        self.ratchet.zeroize();
    }
}

impl Drop for ExportedSessionKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ExportedSessionKey {
    const VERSION: u8 = 1;

    pub(super) fn new(ratchet: &Ratchet, signing_key: Ed25519PublicKey) -> Self {
        let ratchet_index = ratchet.index();
        let mut ratchet_bytes = Box::new([0u8; Ratchet::RATCHET_LENGTH]);

        ratchet_bytes.copy_from_slice(ratchet.as_bytes());

        Self { ratchet_index, ratchet: ratchet_bytes, signing_key }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_with_version(Self::VERSION)
    }

    fn to_bytes_with_version(&self, version: u8) -> Vec<u8> {
        let index = self.ratchet_index.to_be_bytes();

        [[version].as_ref(), index.as_ref(), self.ratchet.as_ref(), self.signing_key.as_bytes()]
            .concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionKeyDecodeError> {
        let mut cursor = Cursor::new(bytes);
        Self::decode_key(Self::VERSION, &mut cursor)
    }

    pub fn to_base64(&self) -> String {
        let mut bytes = self.to_bytes();

        let ret = base64_encode(&bytes);

        bytes.zeroize();

        ret
    }

    pub fn from_base64(key: &str) -> Result<Self, SessionKeyDecodeError> {
        let mut bytes = base64_decode(key)?;
        let ret = Self::from_bytes(&bytes);

        bytes.zeroize();

        ret
    }

    fn decode_key(
        expected_version: u8,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<ExportedSessionKey, SessionKeyDecodeError> {
        let mut version = [0u8; 1];
        let mut index = [0u8; 4];
        let mut ratchet = Box::new([0u8; 128]);
        let mut public_key = [0u8; Ed25519PublicKey::LENGTH];

        cursor.read_exact(&mut version)?;

        if version[0] != expected_version {
            Err(SessionKeyDecodeError::Version(expected_version, version[0]))
        } else {
            cursor.read_exact(&mut index)?;
            cursor.read_exact(ratchet.as_mut_slice())?;
            cursor.read_exact(&mut public_key)?;

            let signing_key = Ed25519PublicKey::from_slice(&public_key)?;
            let ratchet_index = u32::from_be_bytes(index);

            Ok(ExportedSessionKey { ratchet_index, ratchet, signing_key })
        }
    }
}

impl SessionKey {
    const VERSION: u8 = 2;

    pub(super) fn new(ratchet: &Ratchet, signing_key: Ed25519PublicKey) -> Self {
        let session_key = ExportedSessionKey::new(ratchet, signing_key);

        Self {
            session_key,
            signature: Ed25519Signature::from_slice(&[0; Ed25519Signature::LENGTH])
                .expect("Can't create an empty signature"),
        }
    }

    pub fn to_signature_bytes(&self) -> Vec<u8> {
        self.session_key.to_bytes_with_version(Self::VERSION)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_signature_bytes();
        bytes.extend(self.signature.to_bytes());

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SessionKeyDecodeError> {
        let mut cursor = Cursor::new(bytes);
        let session_key = ExportedSessionKey::decode_key(Self::VERSION, &mut cursor)?;

        let mut signature = [0u8; Ed25519Signature::LENGTH];

        cursor.read_exact(&mut signature)?;
        let signature = Ed25519Signature::from_slice(&signature)?;

        let decoded = cursor.into_inner();

        session_key
            .signing_key
            .verify(&decoded[..decoded.len() - Ed25519Signature::LENGTH], &signature)?;

        Ok(Self { session_key, signature })
    }

    pub fn to_base64(&self) -> String {
        let mut bytes = self.to_bytes();
        let ret = base64_encode(&bytes);

        bytes.zeroize();

        ret
    }

    pub fn from_base64(key: &str) -> Result<Self, SessionKeyDecodeError> {
        let mut bytes = base64_decode(key)?;
        let ret = Self::from_bytes(&bytes);

        bytes.zeroize();

        ret
    }
}

impl Serialize for SessionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut encoded = self.to_base64();
        let ret = encoded.serialize(serializer);

        encoded.zeroize();

        ret
    }
}

impl<'de> Deserialize<'de> for SessionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut session_key = String::deserialize(deserializer)?;
        let ret = Self::from_base64(&session_key).map_err(serde::de::Error::custom);

        session_key.zeroize();

        ret
    }
}

impl Serialize for ExportedSessionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut encoded = self.to_base64();
        let ret = encoded.serialize(serializer);

        encoded.zeroize();

        ret
    }
}

impl<'de> Deserialize<'de> for ExportedSessionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut session_key = String::deserialize(deserializer)?;
        let ret = Self::from_base64(&session_key).map_err(serde::de::Error::custom);

        session_key.zeroize();

        ret
    }
}

#[cfg(test)]
mod test {
    use crate::megolm::{ExportedSessionKey, GroupSession, InboundGroupSession, SessionKey};

    #[test]
    fn session_key_serialization() -> Result<(), anyhow::Error> {
        let session = GroupSession::new();

        let key = session.session_key();

        let serialized = serde_json::to_string(&key)?;
        let deserialized: SessionKey = serde_json::from_str(&serialized)?;

        assert_eq!(key.session_key.ratchet, deserialized.session_key.ratchet);
        assert_eq!(key.session_key.ratchet_index, deserialized.session_key.ratchet_index);
        assert_eq!(key.session_key.signing_key, deserialized.session_key.signing_key);
        assert_eq!(key.signature, deserialized.signature);

        Ok(())
    }

    #[test]
    fn exported_session_key_serialization() -> Result<(), anyhow::Error> {
        let session = GroupSession::new();
        let mut session = InboundGroupSession::from(&session);

        let key = session.export_at(0).expect(
            "A freshly created inbound session can always be exported at the initial index",
        );

        let serialized = serde_json::to_string(&key)?;
        let deserialized: ExportedSessionKey = serde_json::from_str(&serialized)?;

        assert_eq!(key.ratchet, deserialized.ratchet);
        assert_eq!(key.ratchet_index, deserialized.ratchet_index);
        assert_eq!(key.signing_key, deserialized.signing_key);

        Ok(())
    }
}
