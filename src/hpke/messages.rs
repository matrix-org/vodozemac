// Copyright 2026 The Matrix.org Foundation C.I.C.
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

#[cfg(doc)]
use super::EstablishedHpkeChannel;
use crate::{Curve25519PublicKey, base64_decode, base64_encode, hpke::error::MessageDecodeError};

/// The initial message, sent by the HPKE channel sender.
///
/// This message embeds the public key of the message creator allowing the other
/// side to establish a channel using this message.
///
/// This key is *unauthenticated* so authentication needs to happen out-of-band
/// in order for the established channel to become secure.
#[derive(Debug, PartialEq, Eq)]
pub struct InitialMessage {
    /// The ephemeral public key that was used to establish the HPKE channel.
    pub encapsulated_key: Curve25519PublicKey,
    /// The ciphertext of the initial message.
    pub ciphertext: Vec<u8>,
}

impl InitialMessage {
    /// Encode the message as a string.
    ///
    /// This prepends the Curve25519 public key bytes to the ciphertext bytes
    /// before it base64 encodes the bytestring.
    pub fn encode(&self) -> String {
        let Self { encapsulated_key, ciphertext } = self;

        let bytes = [encapsulated_key.to_bytes().as_slice(), ciphertext].concat();

        base64_encode(bytes)
    }

    /// Attempt do decode a string into a [`InitialMessage`].
    pub fn decode(message: &str) -> Result<Self, MessageDecodeError> {
        let (encapsulated_key, ciphertext) = decode_message_with_byte_prefix(message)?;

        Ok(Self { encapsulated_key: Curve25519PublicKey::from_bytes(encapsulated_key), ciphertext })
    }
}

/// The initial response, sent by the HPKE channel receiver.
///
/// This message embeds a random base nonce which the other side can use to
/// establish bidirectional communication over a HPKE channel.
#[derive(Debug)]
pub struct InitialResponse {
    /// The randomly generated base response nonce.
    pub base_response_nonce: [u8; 32],
    /// The ciphertext of the initial message.
    pub ciphertext: Vec<u8>,
}

impl InitialResponse {
    /// Encode the message as a string.
    ///
    /// This prepends the base response nonce bytes to the ciphertext bytes
    /// before it base64 encodes the bytestring.
    pub fn encode(&self) -> String {
        let Self { base_response_nonce, ciphertext } = self;

        let bytes = [base_response_nonce.as_slice(), ciphertext].concat();

        base64_encode(bytes)
    }

    /// Attempt do decode a string into a [`InitialResponse`].
    pub fn decode(message: &str) -> Result<Self, MessageDecodeError> {
        let (base_response_nonce, ciphertext) = decode_message_with_byte_prefix(message)?;

        Ok(Self { base_response_nonce, ciphertext })
    }
}

fn decode_message_with_byte_prefix(
    message: &str,
) -> Result<([u8; 32], Vec<u8>), MessageDecodeError> {
    let bytes = base64_decode(message)?;

    bytes
        .split_first_chunk::<32>()
        .map(|(nonce, ciphertext)| (nonce.to_owned(), ciphertext.to_owned()))
        .ok_or(MessageDecodeError::MessageIncomplete)
}

/// An encrypted message a [`EstablishedHpkeChannel`] channel has sent.
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
            message.encapsulated_key.to_base64(),
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
