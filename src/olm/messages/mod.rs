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

pub use message::{InterolmMessage, Message};
pub use pre_key::{InterolmPreKeyMessage, PreKeyMessage};
use serde::{Deserialize, Serialize};

use crate::{Curve25519PublicKey, DecodeError};

/// A type covering all possible messages supported by vodozemac.
///
/// Includes both normal and pre-key messages of both the native and Interolm
/// message variants.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyMessage {
    Native(AnyNativeMessage),
    #[cfg(feature = "interolm")]
    Interolm(AnyInterolmMessage),
}

impl From<AnyNativeMessage> for AnyMessage {
    fn from(value: AnyNativeMessage) -> Self {
        Self::Native(value)
    }
}

impl From<AnyInterolmMessage> for AnyMessage {
    fn from(value: AnyInterolmMessage) -> Self {
        Self::Interolm(value)
    }
}

/// A type covering all possible "normal" (non-prekey) messages supported by
/// vodozemac.
///
/// Includes both the native and Interolm message variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyNormalMessage<'a> {
    Native(&'a Message),
    #[cfg(feature = "interolm")]
    Interolm(&'a InterolmMessage),
}

impl AnyNormalMessage<'_> {
    pub(crate) fn ratchet_key(&self) -> Curve25519PublicKey {
        match self {
            AnyNormalMessage::Native(m) => m.ratchet_key,
            AnyNormalMessage::Interolm(m) => m.ratchet_key,
        }
    }

    pub(crate) fn chain_index(&self) -> u64 {
        match self {
            AnyNormalMessage::Native(m) => m.chain_index,
            AnyNormalMessage::Interolm(m) => m.counter.into(),
        }
    }
}

/// A type covering all pre-key messages supported by vodozemac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyPreKeyMessage {
    Native(PreKeyMessage),
    #[cfg(feature = "interolm")]
    Interolm(InterolmPreKeyMessage),
}

impl From<PreKeyMessage> for AnyPreKeyMessage {
    fn from(value: PreKeyMessage) -> Self {
        AnyPreKeyMessage::Native(value)
    }
}

#[cfg(feature = "interolm")]
impl From<InterolmPreKeyMessage> for AnyPreKeyMessage {
    fn from(value: InterolmPreKeyMessage) -> Self {
        AnyPreKeyMessage::Interolm(value)
    }
}

#[cfg(feature = "interolm")]
impl From<InterolmPreKeyMessage> for AnyInterolmMessage {
    fn from(value: InterolmPreKeyMessage) -> Self {
        Self::PreKey(value)
    }
}

/// A type representing the native Olm message types.
///
/// Olm uses two types of messages. The underlying transport protocol must
/// provide a means for recipients to distinguish between them.
///
/// [`AnyNativeMessage`] provides [`Serialize`] and [`Deserialize`]
/// implementations that are compatible with [Matrix].
///
/// The type is called "native" because we also support Interolm messages.
///
/// [Matrix]: https://spec.matrix.org/latest/client-server-api/#molmv1curve25519-aes-sha2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyNativeMessage {
    /// A normal message, contains only the ciphertext and metadata to decrypt
    /// it.
    Normal(Message),
    /// A pre-key message, contains metadata to establish a [`Session`] as well
    /// as a [`Message`].
    ///
    /// [`Session`]: crate::olm::Session
    PreKey(PreKeyMessage),
}

impl From<Message> for AnyNativeMessage {
    fn from(m: Message) -> Self {
        Self::Normal(m)
    }
}

impl From<PreKeyMessage> for AnyNativeMessage {
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

impl Serialize for AnyNativeMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (message_type, ciphertext) = self.clone().to_parts();

        let message = MessageSerdeHelper { message_type, ciphertext };

        message.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AnyNativeMessage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = MessageSerdeHelper::deserialize(d)?;

        AnyNativeMessage::from_parts(value.message_type, &value.ciphertext)
            .map_err(serde::de::Error::custom)
    }
}

impl AnyNativeMessage {
    /// Create an `AnyNativeMessage` from a message type and a ciphertext.
    pub fn from_parts(message_type: usize, ciphertext: &str) -> Result<Self, DecodeError> {
        match message_type {
            0 => Ok(Self::PreKey(PreKeyMessage::try_from(ciphertext)?)),
            1 => Ok(Self::Normal(Message::try_from(ciphertext)?)),
            m => Err(DecodeError::MessageType(m)),
        }
    }

    /// Get the message as a byte array.
    pub fn message(&self) -> &[u8] {
        match self {
            AnyNativeMessage::Normal(m) => &m.ciphertext,
            AnyNativeMessage::PreKey(m) => &m.message.ciphertext,
        }
    }

    /// Get the type of the message.
    pub fn message_type(&self) -> MessageType {
        match self {
            AnyNativeMessage::Normal(_) => MessageType::Normal,
            AnyNativeMessage::PreKey(_) => MessageType::PreKey,
        }
    }

    /// Convert the `AnyNativeMessage` into a message type, and base64 encoded
    /// message tuple.
    pub fn to_parts(self) -> (usize, String) {
        let message_type = self.message_type();

        match self {
            AnyNativeMessage::Normal(m) => (message_type.into(), m.to_base64()),
            AnyNativeMessage::PreKey(m) => (message_type.into(), m.to_base64()),
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

#[cfg(feature = "interolm")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyInterolmMessage {
    /// A normal message, contains only the ciphertext and metadata to decrypt
    /// it.
    Normal(InterolmMessage),
    /// A pre-key message, contains metadata to establish a [`Session`] as well
    /// as a [`Message`].
    ///
    /// [`Session`]: crate::olm::Session
    PreKey(InterolmPreKeyMessage),
}

#[cfg(test)]
use olm_rs::session::OlmMessage as LibolmMessage;

#[cfg(test)]
impl From<LibolmMessage> for AnyNativeMessage {
    fn from(other: LibolmMessage) -> Self {
        let (message_type, ciphertext) = other.to_tuple();

        Self::from_parts(message_type.into(), &ciphertext).expect("Can't decode a libolm message")
    }
}

#[cfg(test)]
impl From<AnyNativeMessage> for LibolmMessage {
    fn from(value: AnyNativeMessage) -> LibolmMessage {
        match value {
            AnyNativeMessage::Normal(m) => {
                LibolmMessage::from_type_and_ciphertext(1, m.to_base64())
                    .expect("Can't create a valid libolm message")
            }
            AnyNativeMessage::PreKey(m) => {
                LibolmMessage::from_type_and_ciphertext(0, m.to_base64())
                    .expect("Can't create a valid libolm pre-key message")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use assert_matches::assert_matches;
    use serde_json::json;

    use super::*;
    use crate::{run_corpus, utilities::base64_decode, Curve25519PublicKey};

    const PRE_KEY_MESSAGE: &str = "AwoghAEuxPZ+w7M3pgUae4tDNiggUpOsQ/zci457VAti\
                                   AEYSIO3xOKRDBWKicIfxjSmYCYZ9DD4RMLjvvclbMlE5\
                                   yIEWGiApLrCr853CKlPpW4Bi7S8ykRcejJ0lq7AfYLXK\
                                   CjKdHSJPAwoghw3+P+cajhWj9Qzp5g87h+tbpiuh5wEa\
                                   eUppqmWqug4QASIgRhZ2cgZcIWQbIa23R7U4y1Mo1R/t\
                                   LCaMU+xjzRV5smGsCrJ6AHwktg";

    const MESSAGE: &str = "AwogI7JhE/UsMZqXKb3xV6kUZWoJc6jTm2+AIgWYmaETIR0QASIQ\
                           +X2zb7kEX/3JvoLspcNBcLWOFXYpV0nS";

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
    fn from_interolm() {
        let message =
            "MwgCEiEF/VRCSPW3XOxQK75pnA18atUmaj4KSP5E3Fhk8QZMdkAaIQVzGcWwnUJF3Y83c3E7V/B1\
             sdAdPO0Igal5I2ak4xw9fCJCMwohBQH58JyqI+8NqoaTYKB/4h4GCtiXpRvg+WLm6JTgRsNgEAAY\
             ACIQ2N/SJfeTaikQb8DmRWja6Vkzmhm1yBq8KAEwAQ==";

        let identity_key =
            Curve25519PublicKey::from_base64("BXMZxbCdQkXdjzdzcTtX8HWx0B087QiBqXkjZqTjHD18")
                .expect("The type-prefixed Curve25519 can be decoded");

        let parsed = InterolmPreKeyMessage::from_base64(message)
            .expect("We can parse Interolm pre-key messages");

        assert_eq!(
            identity_key, parsed.identity_key,
            "The identity key from the message matches the static identity key"
        );

        let bytes = base64_decode(message).unwrap();
        let encoded = parsed.to_bytes();

        assert_eq!(bytes, encoded);
    }

    #[test]
    fn from_json() -> Result<()> {
        let value = json!({
            "type": 0u8,
            "body": PRE_KEY_MESSAGE,
        });

        let message: AnyNativeMessage = serde_json::from_value(value.clone())?;
        assert_matches!(message, AnyNativeMessage::PreKey(_));

        let serialized = serde_json::to_value(message)?;
        assert_eq!(value, serialized, "The serialization cycle isn't a noop");

        let value = json!({
            "type": 1u8,
            "body": MESSAGE,
        });

        let message: AnyNativeMessage = serde_json::from_value(value.clone())?;
        assert_matches!(message, AnyNativeMessage::Normal(_));

        let serialized = serde_json::to_value(message)?;
        assert_eq!(value, serialized, "The serialization cycle isn't a noop");

        Ok(())
    }

    #[test]
    fn from_parts() -> Result<()> {
        let message = AnyNativeMessage::from_parts(0, PRE_KEY_MESSAGE)?;
        assert_matches!(message, AnyNativeMessage::PreKey(_));
        assert_eq!(
            message.message_type(),
            MessageType::PreKey,
            "Expected message to be recognized as a pre-key Olm message."
        );

        assert_eq!(message.to_parts(), (0, PRE_KEY_MESSAGE.to_string()), "Roundtrip not identity.");

        let message = AnyNativeMessage::from_parts(1, MESSAGE)?;
        assert_eq!(
            message.message_type(),
            MessageType::Normal,
            "Expected message to be recognized as a normal Olm message."
        );
        assert_eq!(message.to_parts(), (1, MESSAGE.to_string()), "Roundtrip not identity.");

        AnyNativeMessage::from_parts(3, PRE_KEY_MESSAGE)
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
