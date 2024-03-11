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

use thiserror::Error;

#[cfg(doc)]
use super::EstablishedEcies;
use crate::{base64_decode, base64_encode, Curve25519PublicKey, KeyError};

/// The error type for the ECIES message decoding failures.
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    /// The initial message could not have been decoded, it's missing the `|`
    /// separator.
    #[error("The initial message is missing the | separator")]
    MissingSeparator,
    /// The initial message could not have been decoded, the embedded Curve25519
    /// key is malformed.
    #[error("The embedded ephemeral Curve25519 key could not have been decoded: {0:?}")]
    KeyError(#[from] KeyError),
    /// The ciphertext is not valid base64.
    #[error("The ciphertext could not have been decoded from a base64 string: {0:?}")]
    Base64(#[from] base64::DecodeError),
}

/// The initial message, sent by the ECIES channel establisher.
///
/// This message embeds the public key of the message creator allowing the other
/// side to establish a channel using this message.
///
/// This key is *unauthenticated* so authentication needs to happen out-of-band
/// in order for the established channel to become secure.
#[derive(Debug, PartialEq, Eq)]
pub struct InitialMessage {
    /// The ephemeral public key that was used to establish the ECIES channel.
    pub public_key: Curve25519PublicKey,
    /// The ciphertext of the initial message.
    pub ciphertext: Vec<u8>,
}

impl InitialMessage {
    /// Encode the message as a string.
    ///
    /// The string will contain the base64-encoded Curve25519 public key and the
    /// ciphertext of the message separated by a `|`.
    pub fn encode(&self) -> String {
        let ciphertext = base64_encode(&self.ciphertext);
        let key = self.public_key.to_base64();

        format!("{ciphertext}|{key}")
    }

    /// Attempt do decode a string into a [`InitialMessage`].
    pub fn decode(message: &str) -> Result<Self, MessageDecodeError> {
        match message.split_once('|') {
            Some((ciphertext, key)) => {
                let public_key = Curve25519PublicKey::from_base64(key)?;
                let ciphertext = base64_decode(ciphertext)?;

                Ok(Self { ciphertext, public_key })
            }
            None => Err(MessageDecodeError::MissingSeparator),
        }
    }
}

/// An encrypted message a [`EstablishedEcies`] channel has sent.
#[derive(Debug)]
pub struct Message {
    /// The ciphertext of the message.
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Encode the message as a string.
    ///
    /// The ciphertext bytes will be encoded using unpadded base64.
    pub fn encode(&self) -> String {
        base64_encode(&self.ciphertext)
    }

    /// Attempt do decode a base64 string into a [`Message`].
    pub fn decode(message: &str) -> Result<Self, MessageDecodeError> {
        Ok(Self { ciphertext: base64_decode(message)? })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const INITIAL_MESSAGE: &str = "3On7QFJyLQMAErua9K/yIOcJALvuMYax1AW0iWgf64AwtSMZXwAA012Q|9yA/CX8pJKF02Prd75ZyBQHg3fGTVVGDNl86q1z17Us";
    const MESSAGE: &str = "ZmtSLdzMcyjC5eV6L8xBI6amsq7gDNbCjz1W5OjX4Z8W";
    const PUBLIC_KEY: &str = "9yA/CX8pJKF02Prd75ZyBQHg3fGTVVGDNl86q1z17Us";

    #[test]
    fn initial_message() {
        let message = InitialMessage::decode(INITIAL_MESSAGE)
            .expect("We should be able to decode our known-valid initial message");

        assert_eq!(
            message.public_key.to_base64(),
            PUBLIC_KEY,
            "The decoded public key should match the expected one"
        );

        let encoded = message.encode();
        assert_eq!(INITIAL_MESSAGE, encoded);
    }

    #[test]
    fn message() {
        let message = Message::decode(MESSAGE)
            .expect("We should be able to decode our known-valid initial message");

        let encoded = message.encode();
        assert_eq!(MESSAGE, encoded);
    }
}
