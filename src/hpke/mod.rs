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

//! Implementation of a [hybrid public encryption scheme].
//!
//! [hybrid public encryption scheme]: https://www.rfc-editor.org/rfc/rfc9180.html
//!
//! # Examples
//!
//! ```
//! use vodozemac::hpke::*;
//!
//! let plaintext = b"It's a secret to everybody";
//!
//! let alice = HpkeSenderChannel::new();
//! let bob = HpkeRecipientChannel::new();
//!
//! let SenderCreationResult { channel: mut alice, message } = alice
//!     .establish_channel(bob.public_key(), plaintext, &[]);
//!
//! let RecipientCreationResult { channel: mut bob, message } = bob.establish_channel(&message, &[])?;
//!
//! assert_eq!(
//!     message, plaintext,
//!     "The decrypted plaintext should match our initial plaintext"
//! );
//!
//! // Now we need to establish communication in the other direction, Bob
//! // needs to encrypt and send an initial reply to Alice.
//!
//! let plaintext = b"Not a secret to me!";
//!
//! let BidirectionalCreationResult { channel: mut bob, message } = bob.establish_bidirectional_channel(plaintext, &[]);
//! let BidirectionalCreationResult { channel: mut alice, message} = alice.establish_bidirectional_channel(&message, &[])?;
//!
//! assert_eq!(message, plaintext);
//!
//! // We now exchange the check code out-of-band and compare it.
//! if alice.check_code() != bob.check_code() {
//!     panic!("The check code must match; possible active MITM attack in progress");
//! }
//!
//! let message = bob.seal(b"Another plaintext", &[]);
//! let decrypted = alice.open(&message, &[])?;
//!
//! assert_eq!(decrypted, b"Another plaintext");
//! # Ok::<(), anyhow::Error>(())
//! ```

mod check_code;
mod error;
mod messages;
mod recipient;
mod response_context;
mod sender;

pub use check_code::*;
pub use error::*;
use hpke::{
    aead::{AeadCtxR, AeadCtxS, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
pub use messages::*;
pub use recipient::*;
use response_context::CreateResponseContext;
pub use sender::*;

use crate::Curve25519PublicKey;

const MATRIX_QR_LOGIN_INFO_PREFIX: &str = "MATRIX_QR_CODE_LOGIN";

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

type SenderContext = AeadCtxS<Aead, Kdf, Kem>;
type RecipientContext = AeadCtxR<Aead, Kdf, Kem>;
type SenderResponseContext = AeadCtxR<Aead, Kdf, Kem>;
type RecipientResponseContext = AeadCtxS<Aead, Kdf, Kem>;

/// The possible device roles for an HPKE channel, indicating whether the
/// device is initiating the channel or receiving/responding as the other side
/// of the initiation.
enum Role {
    /// The role representing the side that sent the initial message.
    Sender {
        /// The established HPKE sender context.
        context: SenderContext,
        /// The HPKE response context enabling the sender to receive messages
        /// from the recipient.
        response_context: SenderResponseContext,
    },
    /// The role representing the side that received the initial message and
    /// sent the initial response.
    Recipient {
        /// The established HPKE recipient context.
        context: RecipientContext,
        /// The HPKE response context enabling the recipient to send messages
        /// to the sender.
        response_context: RecipientResponseContext,
    },
}

impl std::fmt::Debug for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Sender { .. } => f.write_str("Sender"),
            Role::Recipient { .. } => f.write_str("Recipient"),
        }
    }
}

impl Role {
    fn construct_info_string(
        &self,
        partial_info: &str,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> String {
        match self {
            Role::Recipient { .. } => {
                // we are Device G. Gp = our_public_key, Sp = their_public_key
                format!(
                    "{partial_info}|{}|{}",
                    our_public_key.to_base64(),
                    their_public_key.to_base64(),
                )
            }
            Role::Sender { .. } => {
                // we are Device S. Gp = their_public_key, Sp = our_public_key
                format!(
                    "{partial_info}|{}|{}",
                    their_public_key.to_base64(),
                    our_public_key.to_base64(),
                )
            }
        }
    }

    fn check_code_info(
        &self,
        app_info: &str,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> String {
        let partial_info = format!("{app_info}_CHECKCODE");
        self.construct_info_string(&partial_info, our_public_key, their_public_key)
    }

    fn check_code(
        &self,
        app_info: &str,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> CheckCode {
        let mut bytes = [0u8; 2];
        let info = self.check_code_info(app_info, our_public_key, their_public_key);

        let ret = match self {
            Role::Sender { context, .. } => context.export(info.as_bytes(), &mut bytes),
            Role::Recipient { context, .. } => context.export(info.as_bytes(), &mut bytes),
        };

        #[allow(clippy::expect_used)]
        ret.expect("We should be able to generate a check code, as it's just two bytes");

        CheckCode { bytes }
    }
}

struct UnidirectionalHkpeChannel<T> {
    /// The established HPKE context.
    context: T,

    /// The application prefix which will be used as the info string to derive
    /// secrets.
    application_info_prefix: String,

    /// Our own Curve25519 public key which was used to establish the HPKE
    /// channel.
    our_public_key: Curve25519PublicKey,

    /// The other side's Curve25519 public key which was used to establish the
    /// HPKE channel.
    their_public_key: Curve25519PublicKey,
}

/// The result of the creation of a bidirectional and fully established HPKE
/// channel.
pub struct BidirectionalCreationResult<T> {
    /// The established HPKE channel.
    pub channel: EstablishedHpkeChannel,
    /// The plaintext of the initial message.
    pub message: T,
}

/// A fully established HPKE channel.
///
/// This channel allows full bidirecional communication with the other side.
pub struct EstablishedHpkeChannel {
    /// Our own Curve25519 public key which was used to establish the HPKE
    /// channel.
    our_public_key: Curve25519PublicKey,

    /// The other side's Curve25519 public key which was used to establish the
    /// HPKE channel.
    their_public_key: Curve25519PublicKey,

    /// Our device's role in the HPKE channel, i.e. are we the initiator
    /// (device S) or the recipient (device G)?
    role: Role,

    /// The check code, generated on both devices and shared out-of-band, which
    /// needs to match to ensure both sides are using the same secret.
    check_code: CheckCode,
}

impl std::fmt::Debug for EstablishedHpkeChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedHpkeChannel")
            .field("our_public_key", &self.our_public_key)
            .field("their_public_key", &self.their_public_key)
            .field("check_code", &self.check_code)
            .field("role", &self.role)
            .finish()
    }
}

impl EstablishedHpkeChannel {
    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side so that it can
    /// complete the HPKE channel establishment.
    pub const fn public_key(&self) -> Curve25519PublicKey {
        self.our_public_key
    }

    /// Get the [`Curve25519PublicKey`] of the other participant in this
    /// [`EstablishedHpkeChannel`].
    pub const fn their_public_key(&self) -> Curve25519PublicKey {
        self.their_public_key
    }

    /// Get the [`CheckCode`] which uniquely identifies this
    /// [`EstablishedHpkeChannel`] session.
    ///
    /// This check code can be used to check that both sides of the session are
    /// indeed using the same shared secret.
    pub fn check_code(&self) -> &CheckCode {
        &self.check_code
    }

    /// Seal the given plaintext using the associated data and this
    /// [`EstablishedHpkeChannel`].
    ///
    /// This method will encrypt the given plaintext for the other side of this
    /// [`EstablishedHpkeChannel`].
    ///
    /// # Panics
    ///
    /// If the message limit is reached. It's possible to seal 2^64 messages
    /// with this channel. The other reason why this might panic if the
    /// additional associated data is too big, it has to be shorter than
    /// 2^64 bytes.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Message {
        let ret = match &mut self.role {
            Role::Sender { context, .. } => context.seal(plaintext, aad),
            Role::Recipient { response_context, .. } => response_context.seal(plaintext, aad),
        };

        #[allow(clippy::expect_used)]
        let ciphertext = ret.expect(
            "We should be able to seal a plaintext, unless we're overflowed the sequence counter",
        );

        Message { ciphertext }
    }

    /// Open the given message with the given additional associated data using
    /// this [`EstablishedHpkeChannel`].
    ///
    /// This method will decrypt the given message which was encrypted using a
    /// matching [`EstablishedHpkeChannel`].
    pub fn open(&mut self, message: &Message, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let ret = match &mut self.role {
            Role::Sender { response_context, .. } => {
                response_context.open(&message.ciphertext, aad)
            }
            Role::Recipient { context, .. } => context.open(&message.ciphertext, aad),
        };

        ret.map_err(|_| Error::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;

    use super::*;
    use crate::Curve25519SecretKey;

    #[test]
    fn test_channel_creation() {
        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let plaintext = b"It's a secret to everybody";

        let SenderCreationResult { message, .. } =
            alice.establish_channel(bob.public_key(), plaintext, &[]);

        assert_ne!(message.ciphertext, plaintext);

        let RecipientCreationResult { message, .. } = bob
            .establish_channel(&message, &[])
            .expect("We should be able to establish the recipient channel");

        assert_eq!(message, plaintext);
    }

    #[test]
    fn test_channel_roundtrip() {
        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let plaintext = b"It's a secret to everybody";

        let SenderCreationResult { channel: alice, message, .. } =
            alice.establish_channel(bob.public_key(), plaintext, &[]);

        assert_ne!(message.ciphertext, plaintext);

        let RecipientCreationResult { channel: bob, message } = bob
            .establish_channel(&message, &[])
            .expect("We should be able to establish the recipient channel");

        assert_eq!(message, plaintext);

        let plaintext = b"Not a secret to me!";

        let BidirectionalCreationResult { message: initial_response, .. } =
            bob.establish_bidirectional_channel(plaintext, &[]);
        assert_ne!(initial_response.ciphertext, plaintext);

        let BidirectionalCreationResult { message: decrypted, .. } = alice
            .establish_bidirectional_channel(&initial_response, &[])
            .expect("We should be able to decrypt the initial response");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn invalid_public_key() {
        let plaintext = b"It's a secret to everybody";

        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();
        let malory = Curve25519SecretKey::new();

        let SenderCreationResult { mut message, .. } =
            alice.establish_channel(bob.public_key(), plaintext, &[]);

        message.encapsulated_key = Curve25519PublicKey::from(&malory);

        bob.establish_channel(&message, &[]).expect_err(
            "The decryption should fail since Malory inserted the \
             wrong public key into the message",
        );
    }

    #[test]
    fn test_info_construction() {
        use crate::types::Curve25519Keypair;

        let app_info = "foobar";
        let our_public_key = Curve25519Keypair::new().public_key;
        let their_public_key = Curve25519Keypair::new().public_key;

        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let SenderCreationResult { channel: alice, message } =
            alice.establish_channel(bob.public_key(), b"", &[]);

        let RecipientCreationResult { channel: bob, message: _ } = bob
            .establish_channel(&message, &[])
            .expect("We should be able to establish the recipient channel");

        let BidirectionalCreationResult { channel: bob, message: initial_response } =
            bob.establish_bidirectional_channel(b"My response", &[]);

        let BidirectionalCreationResult { channel: alice, .. } = alice
            .establish_bidirectional_channel(&initial_response, &[])
            .expect("We should be able to establish the bidirectional channel for Alice");

        let check_code_info1 =
            alice.role.check_code_info(app_info, our_public_key, their_public_key);
        assert_eq!(
            check_code_info1,
            format!("foobar_CHECKCODE|{their_public_key}|{our_public_key}")
        );

        let check_code_info2 = bob.role.check_code_info(app_info, our_public_key, their_public_key);
        assert_eq!(
            check_code_info2,
            format!("foobar_CHECKCODE|{our_public_key}|{their_public_key}")
        );
    }

    #[test]
    fn snapshot_debug() {
        let key = Curve25519PublicKey::from_bytes([0; 32]);

        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let SenderCreationResult { channel: alice, message } =
            alice.establish_channel(bob.public_key(), b"", &[]);

        let RecipientCreationResult { channel: bob, .. } =
            bob.establish_channel(&message, &[]).unwrap();

        let BidirectionalCreationResult { message, .. } =
            bob.establish_bidirectional_channel(b"", &[]);

        let BidirectionalCreationResult { mut channel, .. } =
            alice.establish_bidirectional_channel(&message, &[]).unwrap();

        channel.our_public_key = key;
        channel.their_public_key = key;
        channel.check_code = CheckCode { bytes: [0, 1] };

        assert_debug_snapshot!(channel);
    }
}
