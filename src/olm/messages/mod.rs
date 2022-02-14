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

pub(crate) use message::{DecodedMessage, EncodedMessage};
pub(crate) use pre_key::{DecodedPreKeyMessage, EncodedPrekeyMessage};

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub(super) inner: String,
}

impl Message {
    pub(crate) fn decode(&self) -> Result<DecodedMessage, crate::DecodeError> {
        DecodedMessage::try_from(self.inner.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreKeyMessage {
    pub(super) inner: String,
}

impl PreKeyMessage {
    pub(crate) fn decode(&self) -> Result<DecodedPreKeyMessage, crate::DecodeError> {
        DecodedPreKeyMessage::try_from(self.inner.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OlmMessage {
    Normal(Message),
    PreKey(PreKeyMessage),
}

impl OlmMessage {
    pub fn from_parts(message_type: usize, ciphertext: String) -> Option<Self> {
        match message_type {
            0 => Some(Self::PreKey(PreKeyMessage { inner: ciphertext })),
            1 => Some(Self::Normal(Message { inner: ciphertext })),
            _ => None,
        }
    }

    pub fn ciphertext(&self) -> &str {
        match self {
            OlmMessage::Normal(m) => &m.inner,
            OlmMessage::PreKey(m) => &m.inner,
        }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            OlmMessage::Normal(_) => MessageType::Normal,
            OlmMessage::PreKey(_) => MessageType::PreKey,
        }
    }

    pub fn to_parts(self) -> (usize, String) {
        let message_type = self.message_type();

        match self {
            OlmMessage::Normal(m) => (message_type.into(), m.inner),
            OlmMessage::PreKey(m) => (message_type.into(), m.inner),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub enum MessageType {
    Normal,
    PreKey,
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
        match value {
            MessageType::PreKey => 0,
            MessageType::Normal => 1,
        }
    }
}

#[cfg(test)]
use olm_rs::session::OlmMessage as LibolmMessage;

#[cfg(test)]
impl From<LibolmMessage> for OlmMessage {
    fn from(other: LibolmMessage) -> Self {
        let (message_type, ciphertext) = other.to_tuple();

        match message_type {
            olm_rs::session::OlmMessageType::PreKey => {
                Self::PreKey(PreKeyMessage { inner: ciphertext })
            }
            olm_rs::session::OlmMessageType::Message => Self::Normal(Message { inner: ciphertext }),
        }
    }
}

#[cfg(test)]
impl From<OlmMessage> for LibolmMessage {
    fn from(value: OlmMessage) -> LibolmMessage {
        let ciphertext = value.ciphertext().to_owned();

        match value {
            OlmMessage::Normal(_) => LibolmMessage::from_type_and_ciphertext(1, ciphertext)
                .expect("Can't create a valid libolm message"),
            OlmMessage::PreKey(_) => LibolmMessage::from_type_and_ciphertext(0, ciphertext)
                .expect("Can't create a valid libolm pre-key message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Context, Result};

    use super::*;

    static RAW_MESSAGE: &str = "FOOBAR";

    #[test]
    fn from_to_parts() -> Result<()> {
        // Test pre-key Olm message construction
        let prekey_message = OlmMessage::from_parts(0, RAW_MESSAGE.to_string())
            .context("Failed constructing normal Olm message from ciphertext.")?;
        assert_eq!(
            prekey_message.ciphertext(),
            RAW_MESSAGE,
            "Constructed message content differs from original message."
        );
        assert_eq!(
            prekey_message.message_type(),
            MessageType::PreKey,
            "Expected message to be recognized as a pre-key Olm message."
        );
        assert_eq!(
            prekey_message.to_parts(),
            (0, RAW_MESSAGE.to_string()),
            "Roundtrip not identity."
        );

        // Test normal Olm message construction
        let normal_message = OlmMessage::from_parts(1, RAW_MESSAGE.to_string())
            .context("Failed constructing normal Olm message from ciphertext.")?;
        assert_eq!(
            normal_message.ciphertext(),
            RAW_MESSAGE,
            "Constructed message content differs from original message."
        );
        assert_eq!(
            normal_message.message_type(),
            MessageType::Normal,
            "Expected message to be recognized as a normal Olm message."
        );
        assert_eq!(
            normal_message.to_parts(),
            (1, RAW_MESSAGE.to_string()),
            "Roundtrip not identity."
        );

        // Test unknown message type
        assert_eq!(
            OlmMessage::from_parts(2, RAW_MESSAGE.to_string()),
            None,
            "Testing unknown Olm message type."
        );

        Ok(())
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
}
