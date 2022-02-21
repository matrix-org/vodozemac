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

use prost::Message as ProstMessage;

use super::Message;
use crate::{
    utilities::{base64_decode, base64_encode},
    Curve25519PublicKey, DecodeError,
};

#[derive(Clone, Debug, PartialEq)]
pub struct PreKeyMessage {
    pub one_time_key: Curve25519PublicKey,
    pub base_key: Curve25519PublicKey,
    pub identity_key: Curve25519PublicKey,
    pub message: Message,
}

impl PreKeyMessage {
    const VERSION: u8 = 3;

    pub(crate) fn new(
        one_time_key: Curve25519PublicKey,
        base_key: Curve25519PublicKey,
        identity_key: Curve25519PublicKey,
        message: Message,
    ) -> Self {
        Self { one_time_key, base_key, identity_key, message }
    }

    pub fn from_bytes(message: Vec<u8>) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let message = ProtoBufPreKeyMessage {
            one_time_key: self.one_time_key.as_bytes().to_vec(),
            base_key: self.base_key.as_bytes().to_vec(),
            identity_key: self.identity_key.as_bytes().to_vec(),
            message: self.message.to_bytes(),
        };

        let mut output: Vec<u8> = vec![0u8; message.encoded_len() + 1];
        output[0] = Self::VERSION;

        message
            .encode(&mut output[1..].as_mut())
            .expect("Couldn't encode our message into a protobuf");

        output
    }

    pub fn from_base64(message: &str) -> Result<Self, DecodeError> {
        Self::try_from(message)
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.to_bytes())
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
        let version = *value.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != Self::VERSION {
            Err(DecodeError::InvalidVersion(Self::VERSION, version))
        } else {
            let decoded = ProtoBufPreKeyMessage::decode(&value[1..value.len()])?;
            let one_time_key = Curve25519PublicKey::from_slice(&decoded.one_time_key)?;
            let base_key = Curve25519PublicKey::from_slice(&decoded.base_key)?;
            let identity_key = Curve25519PublicKey::from_slice(&decoded.identity_key)?;

            let message = decoded.message.try_into()?;

            Ok(Self { one_time_key, base_key, identity_key, message })
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
