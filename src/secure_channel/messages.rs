// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{base64_decode, base64_encode, Curve25519PublicKey, KeyError};

#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error("Foobar")]
    MissingSeparator,
    #[error("Foobar")]
    KeyError(#[from] KeyError),
    #[error("Foobar")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Debug)]
pub struct LoginInitiateMessage {
    pub public_key: Curve25519PublicKey,
    pub ciphertext: Vec<u8>,
}

impl LoginInitiateMessage {
    pub fn encode(&self) -> String {
        let ciphertext = base64_encode(&self.ciphertext);
        let key = self.public_key.to_base64();

        format!("{ciphertext}|{key}")
    }

    pub fn decode(foo: &str) -> Result<Self, MessageDecodeError> {
        match foo.split_once('|') {
            Some((ciphertext, key)) => {
                let public_key = Curve25519PublicKey::from_base64(key)?;
                let ciphertext = base64_decode(ciphertext)?;

                Ok(Self { ciphertext, public_key })
            }
            None => Err(MessageDecodeError::MissingSeparator),
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub ciphertext: Vec<u8>,
}

impl Message {
    pub fn encode(&self) -> String {
        base64_encode(&self.ciphertext)
    }

    pub fn decode(foo: &str) -> Result<Self, MessageDecodeError> {
        Ok(Self { ciphertext: base64_decode(foo)? })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecureChannelMessage {
    Initial(LoginInitiateMessage),
    Normal(Message),
}

impl SecureChannelMessage {
    pub fn encode(&self) -> String {
        match self {
            SecureChannelMessage::Initial(m) => m.encode(),
            SecureChannelMessage::Normal(m) => m.encode(),
        }
    }

    pub fn decode(foo: &str) -> Result<Self, MessageDecodeError> {
        if let Ok(message) = LoginInitiateMessage::decode(foo) {
            Ok(message.into())
        } else {
            Message::decode(foo).map(Into::into)
        }
    }
}

impl From<Message> for SecureChannelMessage {
    fn from(value: Message) -> Self {
        Self::Normal(value)
    }
}

impl From<LoginInitiateMessage> for SecureChannelMessage {
    fn from(value: LoginInitiateMessage) -> Self {
        Self::Initial(value)
    }
}

impl Serialize for LoginInitiateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.encode();

        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LoginInitiateMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::decode(&string).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.encode();

        encoded.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::decode(&string).map_err(serde::de::Error::custom)
    }
}
