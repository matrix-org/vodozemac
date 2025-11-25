// Copyright 2025 The Matrix.org Foundation C.I.C.
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

//! Implementation of an hybrid public encryption scheme.

#![allow(missing_docs)]

mod error;
mod messages;

use error::*;
use hpke::{
    Deserializable as _, OpModeS, Serializable,
    aead::{AeadCtxR, AeadCtxS, AeadResponseCtxR, AeadResponseCtxS, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
};
use messages::*;
use rand::rng;

use crate::{Curve25519PublicKey, Curve25519SecretKey};

const MATRIX_QR_LOGIN_INFO_PREFIX: &str = "MATRIX_QR_CODE_LOGIN";

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

type SenderContext = AeadCtxS<Aead, Kdf, Kem>;
type RecipientContext = AeadCtxR<Aead, Kdf, Kem>;
type SenderResponseContext = AeadResponseCtxS<Aead, Kem>;
type RecipientResponseContext = AeadResponseCtxR<Aead, Kem>;

/// A check code that can be used to confirm that two [`EstablishedHpkeChannel`]
/// objects share the same secret. This is supposed to be shared out-of-band to
/// protect against active MITM attacks.
///
/// Since the initiator device can always tell whether a MITM attack is in
/// progress after channel establishment, this code technically carries only a
/// single bit of information, representing whether the initiator has determined
/// that the channel is "secure" or "not secure".
///
/// However, given this will need to be interactively confirmed by the user,
/// there is risk that the user would confirm the dialogue without paying
/// attention to its content. By expanding this single bit into a deterministic
/// two-digit check code, the user is forced to pay more attention by having to
/// enter it instead of just clicking through a dialogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckCode {
    bytes: [u8; 2],
}

impl CheckCode {
    /// Convert the check code to an array of two bytes.
    ///
    /// The bytes can be converted to a more user-friendly representation. The
    /// [`CheckCode::to_digit`] converts the bytes to a two-digit number.
    pub const fn as_bytes(&self) -> &[u8; 2] {
        &self.bytes
    }

    /// Convert the check code to two base-10 numbers.
    ///
    /// The number should be displayed with a leading 0 in case the first digit
    /// is a 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use vodozemac::hpke::CheckCode;
    /// # let check_code: CheckCode = unimplemented!();
    /// let check_code = check_code.to_digit();
    ///
    /// println!("The check code of the HPKE channel is: {check_code:02}");
    /// ```
    pub const fn to_digit(&self) -> u8 {
        let first = (self.bytes[0] % 10) * 10;
        let second = self.bytes[1] % 10;

        first + second
    }
}

#[derive(Debug)]
pub struct InboundCreationResult {
    /// The established HPKE channel.
    pub hpke: EstablishedHpkeChannel,
    /// The plaintext of the initial message.
    pub message: Vec<u8>,
}

pub struct OutboundCreationResult {
    /// The established HPKE channel.
    pub hpke: EstablishedHpkeChannel,
    /// The initial message.
    pub message: InitialMessage,
}

/// The possible device roles for an HPKE channel, indicating whether the
/// device is initiating the channel or receiving/responding as the other side
/// of the initiation.
enum Role {
    Initiator { context: SenderContext, response_context: SenderResponseContext },
    Recipient { context: RecipientContext, response_context: RecipientResponseContext },
}

impl std::fmt::Debug for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Initiator { .. } => f.write_str("Role::Initiator"),
            Role::Recipient { .. } => f.write_str("Role::Recipient"),
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
            Role::Initiator { .. } => {
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
            Role::Initiator { context, .. } => context.export(info.as_bytes(), &mut bytes),
            Role::Recipient { context, .. } => context.export(info.as_bytes(), &mut bytes),
        };

        ret.expect("We should be able to foo");

        CheckCode { bytes }
    }
}

pub struct HpkeSenderChannel {
    application_info_prefix: String,
}

impl HpkeSenderChannel {
    /// Create a new, random, unestablished HPKE session.
    ///
    /// This method will use the `MATRIX_QR_CODE_LOGIN` info. If you are using
    /// this for a different purpose, consider using the
    /// [`HpkeSenderChannel::with_info()`] method.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_info(MATRIX_QR_LOGIN_INFO_PREFIX)
    }

    /// Create a new, random, unestablished HPKE session with the given
    /// application info.
    ///
    /// The application info will be used to derive the various secrets and
    /// provide domain separation.
    pub fn with_info(info: &str) -> Self {
        Self { application_info_prefix: info.to_owned() }
    }

    /// Create an [`EstablishedHpkeChannel`] session using the other side's
    /// Curve25519 public key and an initial plaintext.
    ///
    /// After the channel has been established, we can encrypt messages to send
    /// to the other side. The other side uses the initial message to
    /// establishes the same channel on its side.
    pub fn establish_channel(
        self,
        their_public_key: Curve25519PublicKey,
        initial_plaintext: &[u8],
    ) -> OutboundCreationResult {
        let mut rng = rng();

        let Self { application_info_prefix } = self;

        let their_key =
            <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(their_public_key.as_bytes())
                .expect(
                    "Converting the Dalek public key to the HPKE public key should always work",
                );

        let (encapsulated_key, mut context): (_, SenderContext) = hpke::setup_sender(
            &OpModeS::Base,
            &their_key,
            application_info_prefix.as_bytes(),
            &mut rng,
        )
        .expect("Encapsulating an X25519 public key never fails since the encapsulation is just the bytes of the public key");

        let ciphertext = context
            .seal(initial_plaintext, &[])
            .expect("We should be able to seal the initial plaintext");
        let response_context = context.response_context();

        let encapsulated_key = encapsulated_key.to_bytes();
        let encapsulated_key = Curve25519PublicKey::from_slice(encapsulated_key.as_slice()).expect(
            "Converting from the HPKE public key to the Dalek public key should always work",
        );

        let our_public_key = encapsulated_key;

        let role = Role::Initiator { context, response_context };
        let check_code =
            role.check_code(&application_info_prefix, our_public_key, their_public_key);

        OutboundCreationResult {
            hpke: EstablishedHpkeChannel { our_public_key, their_public_key, role, check_code },
            message: InitialMessage { encapsulated_key, ciphertext },
        }
    }
}

pub struct HpkeRecipientChannel {
    secret_key: Curve25519SecretKey,
    application_info_prefix: String,
}

impl HpkeRecipientChannel {
    /// Create a new, random, unestablished HPKE session.
    ///
    /// This method will use the `MATRIX_QR_CODE_LOGIN` info. If you are using
    /// this for a different purpose, consider using the
    /// [`HpkeRecipientChannel::with_info()`] method.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_info(MATRIX_QR_LOGIN_INFO_PREFIX)
    }

    /// Create a new, random, unestablished HPKE channel with the given
    /// application info.
    ///
    /// The application info will be used to derive the various secrets and
    /// provide domain separation.
    pub fn with_info(info: &str) -> Self {
        Self { secret_key: Curve25519SecretKey::new(), application_info_prefix: info.to_owned() }
    }

    /// Create a [`EstablishedHpkeChannel`] from an [`InitialMessage`] encrypted
    /// by the other side.
    pub fn establish_channel(
        self,
        message: &InitialMessage,
    ) -> Result<InboundCreationResult, Error> {
        let Self { secret_key, application_info_prefix } = self;

        let their_public_key = message.encapsulated_key;
        let our_public_key = Curve25519PublicKey::from(&secret_key);

        let secret_key =
            <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(secret_key.as_bytes()).unwrap();

        let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
            message.encapsulated_key.as_bytes(),
        )
        .unwrap();

        let mut context: RecipientContext = hpke::setup_receiver(
            &hpke::OpModeR::Base,
            &secret_key,
            &encapped_key,
            application_info_prefix.as_bytes(),
        )
        .unwrap();

        let message = context.open(&message.ciphertext, &[]).unwrap();
        let response_context = context.response_context();

        let role = Role::Recipient { context, response_context };

        let check_code =
            role.check_code(&application_info_prefix, our_public_key, their_public_key);

        Ok(InboundCreationResult {
            hpke: EstablishedHpkeChannel { their_public_key, our_public_key, role, check_code },
            message,
        })
    }

    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side to be able to
    /// establish an HPKE channel.
    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(&self.secret_key)
    }
}

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

    pub fn seal(&mut self, plaintext: &[u8]) -> Message {
        let ret = match &mut self.role {
            Role::Initiator { context, .. } => context.seal(plaintext, &[]),
            Role::Recipient { response_context, .. } => response_context.seal(plaintext, &[]),
        };

        let ciphertext = ret.expect(
            "We should be able to seal a plaintext, unless we're overflowed the sequence counter",
        );

        Message { ciphertext }
    }

    pub fn open(&mut self, message: Message) -> Result<Vec<u8>, Error> {
        let ret = match &mut self.role {
            Role::Initiator { response_context, .. } => {
                response_context.open(&message.ciphertext, &[])
            }
            Role::Recipient { context, .. } => context.open(&message.ciphertext, &[]),
        };

        Ok(ret.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_channel_creation() {
        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let OutboundCreationResult { message, .. } =
            alice.establish_channel(bob.public_key(), b"It's a secret to everybody");

        assert_ne!(message.ciphertext, b"It's a secret to everybody");

        let InboundCreationResult { message, .. } = bob
            .establish_channel(&message)
            .expect("We should be able to establish the recipient channel");

        assert_eq!(message, b"It's a secret to everybody");
    }

    #[test]
    fn test_channel_roundtrip() {
        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let OutboundCreationResult { hpke: mut alice, message, .. } =
            alice.establish_channel(bob.public_key(), b"It's a secret to everybody");

        assert_ne!(message.ciphertext, b"It's a secret to everybody");

        let InboundCreationResult { hpke: mut bob, message } = bob
            .establish_channel(&message)
            .expect("We should be able to establish the recipient channel");

        assert_eq!(message, b"It's a secret to everybody");

        let message = bob.seal(b"Foo");
        assert_ne!(message.ciphertext, b"Foo");

        let decrypted = alice.open(message).unwrap();

        assert_eq!(decrypted, b"Foo");
    }

    #[test]
    fn invalid_public_key() {
        let plaintext = b"It's a secret to everybody";

        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();
        let malory = Curve25519SecretKey::new();

        let OutboundCreationResult { mut message, .. } =
            alice.establish_channel(bob.public_key(), plaintext);

        message.encapsulated_key = Curve25519PublicKey::from(&malory);

        bob.establish_channel(&message).expect_err(
            "The decryption should fail since Malory inserted the \
             wrong public key into the message",
        );
    }

    proptest! {
        #[test]
        fn check_code_proptest(bytes in prop::array::uniform2(0u8..) ) {
            let check_code = CheckCode {
                bytes
            };

            let digit = check_code.to_digit();

            prop_assert!(
                (0..=99).contains(&digit),
                "The digit should be in the 0-99 range"
            );
        }
    }
}
