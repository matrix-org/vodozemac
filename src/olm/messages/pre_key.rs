// Copyright 2021 Damir Jelić
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

use std::fmt::Debug;

use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};

use super::Message;
use crate::{
    Curve25519PublicKey, DecodeError,
    olm::SessionKeys,
    utilities::{base64_decode, base64_encode},
};

/// An encrypted Olm pre-key message.
///
/// Contains metadata that is required to establish a [`Session`] and a normal
/// Olm [`Message`].
///
/// [`Session`]: crate::olm::Session
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKeyMessage {
    pub(crate) session_keys: SessionKeys,
    pub(crate) message: Message,
}

impl PreKeyMessage {
    const VERSION: u8 = 3;

    /// The single-use key that was uploaded to a public key directory by the
    /// receiver of the message. Should be used to establish a [`Session`].
    ///
    /// [`Session`]: crate::olm::Session
    pub const fn one_time_key(&self) -> Curve25519PublicKey {
        self.session_keys.one_time_key
    }

    /// The base key, a single use key that was created just in time by the
    /// sender of the message. Should be used to establish a [`Session`].
    ///
    /// [`Session`]: crate::olm::Session
    pub const fn base_key(&self) -> Curve25519PublicKey {
        self.session_keys.base_key
    }

    /// The long term identity key of the sender of the message. Should be used
    /// to establish a [`Session`]
    ///
    /// [`Session`]: crate::olm::Session
    pub const fn identity_key(&self) -> Curve25519PublicKey {
        self.session_keys.identity_key
    }

    /// The collection of all keys required for establishing an Olm [`Session`]
    /// from this pre-key message.
    ///
    /// Other methods on this struct (like [`PreKeyMessage::identity_key()`])
    /// can be used to retrieve individual keys from this collection.
    ///
    /// [`Session`]: crate::olm::Session
    pub const fn session_keys(&self) -> SessionKeys {
        self.session_keys
    }

    /// Returns the globally unique session ID, in base64-encoded form.
    ///
    /// This is a shorthand helper of the [`SessionKeys::session_id()`] method.
    pub fn session_id(&self) -> String {
        self.session_keys.session_id()
    }

    /// The actual message that contains the ciphertext.
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Try to decode the given byte slice as a Olm [`Message`].
    ///
    /// The expected format of the byte array is described in the
    /// [`PreKeyMessage::to_bytes()`] method.
    pub fn from_bytes(message: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    /// Encode the `PreKeyMessage` as an array of bytes.
    ///
    /// Olm `PreKeyMessage`s consist of a one-byte version, followed by a
    /// variable length payload.
    ///
    /// ```text
    /// +--------------+------------------------------------+
    /// | Version Byte | Payload Bytes                      |
    /// +--------------+------------------------------------+
    /// ```
    ///
    /// The payload uses a format based on the Protocol Buffers encoding. It
    /// consists of the following key-value pairs:
    ///
    ///   **Name**  |**Tag**|**Type**|              **Meaning**
    /// :----------:|:-----:|:------:|:----------------------------------------:
    /// One-Time-Key| 0x0A  | String |The public part of Bob's single-use key
    ///   Base-Key  | 0x12  | String |The public part of Alice's single-use key
    /// Identity-Key| 0x1A  | String |The public part of Alice's identity key
    ///   Message   | 0x22  | String |An embedded Olm message
    ///
    /// The last key/value pair in a [`PreKeyMessage`] is a normal Olm
    /// [`Message`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let message = ProtoBufPreKeyMessage {
            one_time_key: self.session_keys.one_time_key.as_bytes().to_vec(),
            base_key: self.session_keys.base_key.as_bytes().to_vec(),
            identity_key: self.session_keys.identity_key.as_bytes().to_vec(),
            message: self.message.to_bytes(),
        };

        let mut output: Vec<u8> = vec![0u8; message.encoded_len() + 1];
        output[0] = Self::VERSION;

        #[allow(clippy::expect_used)]
        message
            .encode(&mut output[1..].as_mut())
            .expect("We should be able to encode a pre-key message into protobuf.");

        output
    }

    /// Try to decode the given string as a Olm [`PreKeyMessage`].
    ///
    /// The string needs to be a base64 encoded byte array that follows the
    /// format described in the [`PreKeyMessage::to_bytes()`] method.
    pub fn from_base64(message: &str) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    /// Encode the [`PreKeyMessage`] as a string.
    ///
    /// This method first calls [`PreKeyMessage::to_bytes()`] and then encodes
    /// the resulting byte array as a string using base64 encoding.
    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
    }

    /// Create a new pre-key message from the session keys and standard message.
    #[cfg(feature = "low-level-api")]
    pub const fn wrap(session_keys: SessionKeys, message: Message) -> Self {
        PreKeyMessage::new(session_keys, message)
    }

    pub(crate) const fn new(session_keys: SessionKeys, message: Message) -> Self {
        Self { session_keys, message }
    }
}

impl Serialize for PreKeyMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let message = self.to_base64();
        serializer.serialize_str(&message)
    }
}

impl<'de> Deserialize<'de> for PreKeyMessage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ciphertext = String::deserialize(d)?;
        PreKeyMessage::from_base64(&ciphertext).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for PreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let decoded = base64_decode(value)?;

        Self::try_from(decoded)
    }
}

impl TryFrom<Vec<u8>> for PreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for PreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let version = *value.first().ok_or(DecodeError::MissingVersion)?;

        if version != Self::VERSION {
            Err(DecodeError::InvalidVersion(Self::VERSION, version))
        } else {
            let decoded = ProtoBufPreKeyMessage::decode(&value[1..value.len()])?;
            let one_time_key = Curve25519PublicKey::from_slice(&decoded.one_time_key)?;
            let base_key = Curve25519PublicKey::from_slice(&decoded.base_key)?;
            let identity_key = Curve25519PublicKey::from_slice(&decoded.identity_key)?;

            let message = decoded.message.try_into()?;

            let session_keys = SessionKeys { one_time_key, identity_key, base_key };

            Ok(Self { session_keys, message })
        }
    }
}

#[derive(Clone, ProstMessage)]
struct ProtoBufPreKeyMessage {
    #[prost(bytes, tag = "1")]
    one_time_key: Vec<u8>,
    #[prost(bytes, tag = "2")]
    base_key: Vec<u8>,
    #[prost(bytes, tag = "3")]
    identity_key: Vec<u8>,
    #[prost(bytes, tag = "4")]
    message: Vec<u8>,
}
