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

mod message;
mod pre_key;

pub use message::Message;
pub use pre_key::PreKeyMessage;
use serde::{Deserialize, Serialize};

use crate::{DecodeError, base64_decode, base64_encode};

/// Enum over the different Olm message types.
///
/// Olm uses two types of messages. The underlying transport protocol must
/// provide a means for recipients to distinguish between them.
///
/// [`OlmMessage`] provides [`Serialize`] and [`Deserialize`] implementations
/// that are compatible with [Matrix].
///
/// [Matrix]: https://spec.matrix.org/latest/client-server-api/#molmv1curve25519-aes-sha2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OlmMessage {
    /// A normal message, contains only the ciphertext and metadata to decrypt
    /// it.
    Normal(Message),
    /// A pre-key message, contains metadata to establish a [`Session`] as well
    /// as a [`Message`].
    ///
    /// [`Session`]: crate::olm::Session
    PreKey(PreKeyMessage),
}

impl From<Message> for OlmMessage {
    fn from(m: Message) -> Self {
        Self::Normal(m)
    }
}

impl From<PreKeyMessage> for OlmMessage {
    fn from(m: PreKeyMessage) -> Self {
        Self::PreKey(m)
    }
}

#[derive(Serialize, Deserialize)]
struct MessageSerdeHelper {
    #[serde(rename = "type")]
    message_type: usize,
    #[serde(rename = "body")]
    ciphertext: String,
}

impl Serialize for OlmMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (message_type, ciphertext) = self.to_parts();
        let message = MessageSerdeHelper { message_type, ciphertext: base64_encode(ciphertext) };

        message.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OlmMessage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = MessageSerdeHelper::deserialize(d)?;
        let ciphertext_bytes = base64_decode(value.ciphertext).map_err(serde::de::Error::custom)?;

        OlmMessage::from_parts(value.message_type, ciphertext_bytes.as_slice())
            .map_err(serde::de::Error::custom)
    }
}

impl OlmMessage {
    /// Create an [`OlmMessage`] from a message type and a ciphertext.
    pub fn from_parts(message_type: usize, ciphertext: &[u8]) -> Result<Self, DecodeError> {
        match message_type {
            0 => Ok(Self::PreKey(PreKeyMessage::from_bytes(ciphertext)?)),
            1 => Ok(Self::Normal(Message::from_bytes(ciphertext)?)),
            m => Err(DecodeError::MessageType(m)),
        }
    }

    /// Get the message's ciphertext as a byte array.
    pub fn message(&self) -> &[u8] {
        match self {
            OlmMessage::Normal(m) => &m.ciphertext,
            OlmMessage::PreKey(m) => &m.message.ciphertext,
        }
    }

    /// Get the type of the message.
    pub const fn message_type(&self) -> MessageType {
        match self {
            OlmMessage::Normal(_) => MessageType::Normal,
            OlmMessage::PreKey(_) => MessageType::PreKey,
        }
    }

    /// Convert the [`OlmMessage`] into a message type, and ciphertext bytes
    /// tuple.
    pub fn to_parts(&self) -> (usize, Vec<u8>) {
        let message_type = self.message_type();

        match self {
            OlmMessage::Normal(m) => (message_type.into(), m.to_bytes()),
            OlmMessage::PreKey(m) => (message_type.into(), m.to_bytes()),
        }
    }
}

/// An enum over the two supported message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// The pre-key message type.
    PreKey = 0,
    /// The normal message type.
    Normal = 1,
}

impl TryFrom<usize> for MessageType {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::PreKey),
            1 => Ok(MessageType::Normal),
            _ => Err(()),
        }
    }
}

impl From<MessageType> for usize {
    fn from(value: MessageType) -> usize {
        value as usize
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use assert_matches::assert_matches;
    use olm_rs::session::OlmMessage as LibolmMessage;
    use serde_json::json;

    use super::*;
    use crate::run_corpus;

    const PRE_KEY_MESSAGE: &str = "AwoghAEuxPZ+w7M3pgUae4tDNiggUpOsQ/zci457VAti\
                                   AEYSIO3xOKRDBWKicIfxjSmYCYZ9DD4RMLjvvclbMlE5\
                                   yIEWGiApLrCr853CKlPpW4Bi7S8ykRcejJ0lq7AfYLXK\
                                   CjKdHSJPAwoghw3+P+cajhWj9Qzp5g87h+tbpiuh5wEa\
                                   eUppqmWqug4QASIgRhZ2cgZcIWQbIa23R7U4y1Mo1R/t\
                                   LCaMU+xjzRV5smGsCrJ6AHwktg";

    const PRE_KEY_MESSAGE_CIPHERTEXT: [u8; 32] = [
        70, 22, 118, 114, 6, 92, 33, 100, 27, 33, 173, 183, 71, 181, 56, 203, 83, 40, 213, 31, 237,
        44, 38, 140, 83, 236, 99, 205, 21, 121, 178, 97,
    ];

    const MESSAGE: &str = "AwogI7JhE/UsMZqXKb3xV6kUZWoJc6jTm2+AIgWYmaETIR0QASIQ\
                           +X2zb7kEX/3JvoLspcNBcLWOFXYpV0nS";

    const MESSAGE_CIPHERTEXT: [u8; 16] =
        [249, 125, 179, 111, 185, 4, 95, 253, 201, 190, 130, 236, 165, 195, 65, 112];

    impl From<OlmMessage> for LibolmMessage {
        fn from(value: OlmMessage) -> LibolmMessage {
            match value {
                OlmMessage::Normal(m) => LibolmMessage::from_type_and_ciphertext(1, m.to_base64())
                    .expect("Can't create a valid libolm message"),
                OlmMessage::PreKey(m) => LibolmMessage::from_type_and_ciphertext(0, m.to_base64())
                    .expect("Can't create a valid libolm pre-key message"),
            }
        }
    }

    impl From<LibolmMessage> for OlmMessage {
        fn from(other: LibolmMessage) -> Self {
            let (message_type, ciphertext) = other.to_tuple();
            let ciphertext_bytes = base64_decode(ciphertext).expect("Can't decode base64");

            Self::from_parts(message_type.into(), ciphertext_bytes.as_slice())
                .expect("Can't decode a libolm message")
        }
    }

    #[test]
    fn message_type_from_usize() {
        assert_eq!(
            MessageType::try_from(0),
            Ok(MessageType::PreKey),
            "0 should denote a pre-key Olm message"
        );
        assert_eq!(
            MessageType::try_from(1),
            Ok(MessageType::Normal),
            "1 should denote a normal Olm message"
        );
        assert!(
            MessageType::try_from(2).is_err(),
            "2 should be recognized as an unknown Olm message type"
        );
    }

    #[test]
    fn from_json() -> Result<()> {
        let value = json!({
            "type": 0u8,
            "body": PRE_KEY_MESSAGE,
        });

        let message: OlmMessage = serde_json::from_value(value.clone())?;
        assert_matches!(message, OlmMessage::PreKey(_));

        let serialized = serde_json::to_value(message)?;
        assert_eq!(value, serialized, "The serialization cycle isn't a noop");

        let value = json!({
            "type": 1u8,
            "body": MESSAGE,
        });

        let message: OlmMessage = serde_json::from_value(value.clone())?;
        assert_matches!(message, OlmMessage::Normal(_));

        let serialized = serde_json::to_value(message)?;
        assert_eq!(value, serialized, "The serialization cycle isn't a noop");

        Ok(())
    }

    #[test]
    fn from_parts() -> Result<()> {
        let message = OlmMessage::from_parts(0, base64_decode(PRE_KEY_MESSAGE)?.as_slice())?;
        assert_matches!(message, OlmMessage::PreKey(_));
        assert_eq!(
            message.message_type(),
            MessageType::PreKey,
            "Expected message to be recognized as a pre-key Olm message."
        );
        assert_eq!(message.message(), PRE_KEY_MESSAGE_CIPHERTEXT);
        assert_eq!(
            message.to_parts(),
            (0, base64_decode(PRE_KEY_MESSAGE)?),
            "Roundtrip not identity."
        );

        let message = OlmMessage::from_parts(1, base64_decode(MESSAGE)?.as_slice())?;
        assert_matches!(message, OlmMessage::Normal(_));
        assert_eq!(
            message.message_type(),
            MessageType::Normal,
            "Expected message to be recognized as a normal Olm message."
        );
        assert_eq!(message.message(), MESSAGE_CIPHERTEXT);
        assert_eq!(message.to_parts(), (1, base64_decode(MESSAGE)?), "Roundtrip not identity.");

        OlmMessage::from_parts(3, base64_decode(PRE_KEY_MESSAGE)?.as_slice())
            .expect_err("Unknown message types can't be parsed");

        Ok(())
    }

    #[test]
    fn fuzz_corpus_decoding() {
        run_corpus("olm-message-decoding", |data| {
            let _ = PreKeyMessage::from_bytes(data);
        });
    }
}
