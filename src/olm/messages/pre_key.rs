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

use prost::Message;

use super::{DecodedMessage, EncodedMessage};
use crate::{utilities::base64_decode, Curve25519PublicKey, DecodeError};

pub(crate) struct DecodedPreKeyMessage {
    pub public_one_time_key: Curve25519PublicKey,
    pub remote_one_time_key: Curve25519PublicKey,
    pub remote_identity_key: Curve25519PublicKey,
    pub message: DecodedMessage,
}

impl TryFrom<&str> for DecodedPreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let decoded = base64_decode(value)?;

        Self::try_from(decoded)
    }
}

impl TryFrom<Vec<u8>> for DecodedPreKeyMessage {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let version = *value.get(0).ok_or(DecodeError::MissingVersion)?;

        if version != EncodedPrekeyMessage::VERSION {
            Err(DecodeError::InvalidVersion(EncodedPrekeyMessage::VERSION, version))
        } else {
            let decoded = ProtoBufPreKeyMessage::decode(&value[1..value.len()])?;
            let one_time_key = Curve25519PublicKey::from_slice(&decoded.one_time_key)?;
            let base_key = Curve25519PublicKey::from_slice(&decoded.base_key)?;
            let identity_key = Curve25519PublicKey::from_slice(&decoded.identity_key)?;

            let message = decoded.message.try_into()?;

            Ok(Self {
                public_one_time_key: one_time_key,
                remote_one_time_key: base_key,
                remote_identity_key: identity_key,
                message,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedPrekeyMessage {
    inner: Vec<u8>,
}

impl EncodedPrekeyMessage {
    const VERSION: u8 = 3;

    pub fn new(
        one_time_key: &Curve25519PublicKey,
        base_key: &Curve25519PublicKey,
        identity_key: &Curve25519PublicKey,
        message: EncodedMessage,
    ) -> Self {
        let message = ProtoBufPreKeyMessage {
            one_time_key: one_time_key.as_bytes().to_vec(),
            base_key: base_key.as_bytes().to_vec(),
            identity_key: identity_key.as_bytes().to_vec(),
            message: message.into(),
        };

        let mut output: Vec<u8> = vec![0u8; message.encoded_len() + 1];
        output[0] = Self::VERSION;

        message
            .encode(&mut output[1..].as_mut())
            .expect("Couldn't encode our message into a protobuf");

        Self { inner: output }
    }
}

impl From<Vec<u8>> for EncodedPrekeyMessage {
    fn from(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }
}

impl AsRef<[u8]> for EncodedPrekeyMessage {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

#[derive(Clone, Message)]
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
