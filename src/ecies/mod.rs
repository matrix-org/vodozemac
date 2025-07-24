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

//! Implementation of an integrated encryption scheme.
//!
//! This module implements
//! [ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme), the
//! elliptic curve variant of the Integrated Encryption Scheme. This is a hybrid
//! encryption scheme, using elliptic curve Diffie-Hellman for shared secret
//! establishment and a symmetric algorithm for encryption of individual
//! messages. It is instantiated with X25519 (Curve25519-based Diffie-Hellman),
//! HMAC-SHA256 as the KDF and ChaCha20-Poly1305 for symmetric encryption.
//!
//! ECIES allows a party (the initiator) to establish a communication channel
//! toward another party (the recipient) given knowledge of only its public key.
//! We assume that this key was obtained in a secure way. This implies that the
//! initiator side is able to tell for sure whether there is an active MITM
//! attack in progress once the channel is established.
//!
//! On the other hand, the initiator's key pair is ephemeral and generated anew
//! for each new channel. This implies the initiator must send their ephemeral
//! public key to the recipient *unauthenticated* so that the recipient can
//! complete the channel establishment on its end. From this it follows that the
//! recipient has no way of knowing who is contacting them, allowing for active
//! MITM attacks on the recipient side.
//!
//! In order to close this vector, an out-of-band confirmation is required to be
//! sent from the initiator device to the recipient device, after which the
//! channel is considered *secure*. The module provides the [`CheckCode`]
//! facility which can be used for this purpose.
//!
//! Throughout this document, we use a naming convention which designates the
//! device initiating an ECIES channel as device S, while the device on the
//! other side (towards which the channel is opened) is designated device G.
//!
//! # Examples
//!
//! ```
//! use vodozemac::ecies::{Ecies, InboundCreationResult, OutboundCreationResult};
//!
//! let plaintext = b"It's a secret to everybody";
//!
//! let alice = Ecies::new();
//! let bob = Ecies::new();
//!
//! let OutboundCreationResult { ecies: mut alice, message } = alice
//!     .establish_outbound_channel(bob.public_key(), plaintext)?;
//!
//! let InboundCreationResult { mut ecies, message } = bob
//!     .establish_inbound_channel(&message)
//!     .expect("We should be able to create an inbound channel");
//!
//! assert_eq!(
//!     message, plaintext,
//!     "The decrypted plaintext should match our initial plaintext"
//! );
//!
//! // We now exchange the check code out-of-band and compare it.
//! if alice.check_code() != ecies.check_code() {
//!     panic!("The check code must match; possible active MITM attack in progress");
//! }
//!
//! let message = ecies.encrypt(b"Another plaintext");
//! let decrypted = alice.decrypt(&message)?;
//!
//! assert_eq!(decrypted, b"Another plaintext");
//! # Ok::<(), anyhow::Error>(())
//! ```

// TODO: Remove this when either clippy stops being annoying or the Zeroize derives properly
// silence the clippy warning.
// See this comment for more info: https://github.com/matrix-org/vodozemac/pull/259#issuecomment-3400639839
#![allow(unused)]

use chacha20poly1305::{ChaCha20Poly1305, Key as Chacha20Key, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use rand::rng;
use sha2::Sha512;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use self::messages::{InitialMessage, Message, MessageDecodeError};
use crate::Curve25519PublicKey;

mod messages;

const MATRIX_QR_LOGIN_INFO_PREFIX: &str = "MATRIX_QR_CODE_LOGIN";

/// The Error type for the ECIES submodule.
#[derive(Debug, Error)]
pub enum Error {
    /// At least one of the keys did not have contributory behaviour and the
    /// resulting shared secret would have been insecure.
    #[error("At least one of the keys did not have contributory behaviour")]
    NonContributoryKey,
    /// Message decryption failed. Either the message was corrupted, the message
    /// was replayed, or the wrong key is being used to decrypt the message.
    #[error("Failed decrypting the message")]
    Decryption,
}

/// A nonce that is used for the [`EstablishedEcies`] channel.
///
/// The nonce is internally represented as a [`u128`]. Each time a new value is
/// retrieved, the counter will get incremented.
struct EciesNonce {
    inner: u128,
}

impl EciesNonce {
    /// Create a new [`EciesNonce`], starting the count from 0.
    const fn new() -> Self {
        Self { inner: 0 }
    }

    /// Get the next nonce value.
    ///
    /// This will increment the underlying counter and return a 12 byte
    /// [`Nonce`] value.
    fn get(&mut self) -> Nonce {
        let current = self.inner;
        let (new_nonce, _) = self.inner.overflowing_add(1);
        self.inner = new_nonce;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&current.to_le_bytes()[..12]);

        Nonce::from_iter(nonce)
    }
}

/// A check code that can be used to confirm that two [`EstablishedEcies`]
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
    /// # use vodozemac::ecies::CheckCode;
    /// # let check_code: CheckCode = unimplemented!();
    /// let check_code = check_code.to_digit();
    ///
    /// println!("The check code of the IECS channel is: {check_code:02}");
    /// ```
    pub const fn to_digit(&self) -> u8 {
        let first = (self.bytes[0] % 10) * 10;
        let second = self.bytes[1] % 10;

        first + second
    }
}

/// The result of an inbound ECIES channel establishment.
#[derive(Debug)]
pub struct InboundCreationResult {
    /// The established ECIES channel.
    pub ecies: EstablishedEcies,
    /// The plaintext of the initial message.
    pub message: Vec<u8>,
}

/// The result of an outbound ECIES channel establishment.
#[derive(Debug)]
pub struct OutboundCreationResult {
    /// The established ECIES channel.
    pub ecies: EstablishedEcies,
    /// The initial message.
    pub message: InitialMessage,
}

/// An unestablished ECIES session.
pub struct Ecies {
    secret_key: EphemeralSecret,
    application_info_prefix: String,
}

/// The possible device roles for an ECIES channel, indicating whether the
/// device is initiating the channel or receiving/responding as the other side
/// of the initiation.
#[derive(Debug, Clone, Copy)]
enum Role {
    Initiator,
    Recipient,
}

impl Ecies {
    /// Create a new, random, unestablished ECIES session.
    ///
    /// This method will use the `MATRIX_QR_CODE_LOGIN` info. If you are using
    /// this for a different purpose, consider using the [`Ecies::with_info()`]
    /// method.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_info(MATRIX_QR_LOGIN_INFO_PREFIX)
    }

    /// Create a new, random, unestablished ECIES session with the given
    /// application info.
    ///
    /// The application info will be used to derive the various secrets and
    /// provide domain separation.
    pub fn with_info(info: &str) -> Self {
        let mut rng = rng();
        let secret_key = EphemeralSecret::random_from_rng(&mut rng);
        let application_info_prefix = info.to_owned();

        Self { secret_key, application_info_prefix }
    }

    /// Create an [`EstablishedEcies`] session using the other side's Curve25519
    /// public key and an initial plaintext.
    ///
    /// After the channel has been established, we can encrypt messages to send
    /// to the other side. The other side uses the initial message to
    /// establishes the same channel on its side.
    pub fn establish_outbound_channel(
        self,
        their_public_key: Curve25519PublicKey,
        initial_plaintext: &[u8],
    ) -> Result<OutboundCreationResult, Error> {
        let our_public_key = self.public_key();
        let shared_secret = self.secret_key.diffie_hellman(&their_public_key.inner);

        if shared_secret.was_contributory() {
            let mut ecies = EstablishedEcies::new(
                &shared_secret,
                our_public_key,
                their_public_key,
                &self.application_info_prefix,
                Role::Initiator,
            );

            let message = ecies.encrypt(initial_plaintext);
            let message =
                InitialMessage { public_key: our_public_key, ciphertext: message.ciphertext };

            Ok(OutboundCreationResult { ecies, message })
        } else {
            Err(Error::NonContributoryKey)
        }
    }

    /// Create a [`EstablishedEcies`] from an [`InitialMessage`] encrypted by
    /// the other side.
    pub fn establish_inbound_channel(
        self,
        message: &InitialMessage,
    ) -> Result<InboundCreationResult, Error> {
        let our_public_key = self.public_key();

        let shared_secret = self.secret_key.diffie_hellman(&message.public_key.inner);

        if shared_secret.was_contributory() {
            let mut ecies = EstablishedEcies::new(
                &shared_secret,
                our_public_key,
                message.public_key,
                &self.application_info_prefix,
                Role::Recipient,
            );

            let nonce = ecies.decryption_nonce.get();
            let message = ecies.decrypt_helper(&nonce, &message.ciphertext)?;

            Ok(InboundCreationResult { ecies, message })
        } else {
            Err(Error::NonContributoryKey)
        }
    }

    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side to be able to
    /// establish an ECIES channel.
    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(&self.secret_key)
    }
}

/// An established ECIES session.
///
/// This session can be used to encrypt and decrypt messages between the two
/// sides of the channel.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EstablishedEcies {
    /// Our own Curve25519 public key which was used to establish the ECIES
    /// channel.
    #[zeroize(skip)]
    our_public_key: Curve25519PublicKey,

    /// The other side's Curve25519 public key which was used to establish the
    /// ECIES channel.
    #[zeroize(skip)]
    their_public_key: Curve25519PublicKey,

    /// A counter which we'll use to create a [`Nonce`] every time we want to
    /// encrypt a message.
    #[zeroize(skip)]
    encryption_nonce: EciesNonce,

    /// A counter which we'll use to create a [`Nonce`] every time we want to
    /// decrypt a message. The other side uses an analogous counter to encrypt
    /// messages.
    #[zeroize(skip)]
    decryption_nonce: EciesNonce,

    /// The key used to encrypt our messages.
    encryption_key: Box<[u8; 32]>,

    /// The key used by the other party to encrypt messages.
    decryption_key: Box<[u8; 32]>,

    /// The check code, generated on both devices and shared out-of-band, which
    /// needs to match to ensure both sides are using the same secret.
    #[zeroize(skip)]
    check_code: CheckCode,

    /// Our device's role in the ECIES channel, i.e. are we the initiator
    /// (device S) or the recipient (device G)?
    #[zeroize(skip)]
    role: Role,
}

impl std::fmt::Debug for EstablishedEcies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedEcies")
            .field("our_public_key", &self.our_public_key)
            .field("their_public_key", &self.their_public_key)
            .field("check_code", &self.check_code)
            .field("role", &self.role)
            .finish()
    }
}

impl EstablishedEcies {
    fn create_check_code(
        shared_secret: &SharedSecret,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
        info: &str,
        role: Role,
    ) -> CheckCode {
        let mut bytes = [0u8; 2];
        let kdf: Hkdf<Sha512> = Hkdf::new(None, shared_secret.as_bytes());

        let info = Self::get_check_code_info(info, role, our_public_key, their_public_key);

        #[allow(clippy::expect_used)]
        kdf.expand(info.as_bytes(), bytes.as_mut_slice()).expect(
            "We should be able to expand the 32-byte long shared secret into a 32 byte key.",
        );

        CheckCode { bytes }
    }

    fn create_key(info: &str, shared_secret: &SharedSecret) -> Box<[u8; 32]> {
        let mut key = Box::new([0u8; 32]);
        let kdf: Hkdf<Sha512> = Hkdf::new(None, shared_secret.as_bytes());

        #[allow(clippy::expect_used)]
        kdf.expand(info.as_bytes(), key.as_mut_slice()).expect(
            "We should be able to expand the 32-byte long shared secret into a 32 byte key.",
        );

        key
    }

    /// Create the encryption key for messages we send into the channel.
    fn create_encryption_key(
        shared_secret: &SharedSecret,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
        app_info: &str,
        role: Role,
    ) -> Box<[u8; 32]> {
        let info = Self::get_encryption_key_info(app_info, role, our_public_key, their_public_key);
        Self::create_key(&info, shared_secret)
    }

    /// Create the decryption key for messages received from the other side of
    /// the channel.
    ///
    /// The decryption key for G is the encryption key for S and vice versa.
    fn create_decryption_key(
        shared_secret: &SharedSecret,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
        app_info: &str,
        role: Role,
    ) -> Box<[u8; 32]> {
        let info = Self::get_decryption_key_info(app_info, role, our_public_key, their_public_key);
        Self::create_key(&info, shared_secret)
    }

    fn new(
        shared_secret: &SharedSecret,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
        app_info: &str,
        role: Role,
    ) -> Self {
        let (encryption_nonce, decryption_nonce) = (EciesNonce::new(), EciesNonce::new());

        let encryption_key = Self::create_encryption_key(
            shared_secret,
            our_public_key,
            their_public_key,
            app_info,
            role,
        );
        let decryption_key = Self::create_decryption_key(
            shared_secret,
            our_public_key,
            their_public_key,
            app_info,
            role,
        );
        let check_code = Self::create_check_code(
            shared_secret,
            our_public_key,
            their_public_key,
            app_info,
            role,
        );

        Self {
            encryption_key,
            decryption_key,
            encryption_nonce,
            decryption_nonce,
            our_public_key,
            their_public_key,
            check_code,
            role,
        }
    }

    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side so that it can
    /// complete the ECIES channel establishment.
    pub const fn public_key(&self) -> Curve25519PublicKey {
        self.our_public_key
    }

    /// Get the [`CheckCode`] which uniquely identifies this
    /// [`EstablishedEcies`] session.
    ///
    /// This check code can be used to check that both sides of the session are
    /// indeed using the same shared secret.
    pub const fn check_code(&self) -> &CheckCode {
        &self.check_code
    }

    fn encryption_key(&self) -> &Chacha20Key {
        #[allow(deprecated)]
        Chacha20Key::from_slice(self.encryption_key.as_slice())
    }

    fn decryption_key(&self) -> &Chacha20Key {
        #[allow(deprecated)]
        Chacha20Key::from_slice(self.decryption_key.as_slice())
    }

    /// Encrypt the given plaintext using this [`EstablishedEcies`] session.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Message {
        let nonce = self.encryption_nonce.get();

        let cipher = ChaCha20Poly1305::new(self.encryption_key());
        #[allow(clippy::expect_used)]
        let ciphertext = cipher.encrypt(&nonce, plaintext).expect(
            "We should always be able to encrypt a message since we provide the correct nonce",
        );

        Message { ciphertext }
    }

    /// Decrypt the given message using this [`EstablishedEcies`] session.
    pub fn decrypt(&mut self, message: &Message) -> Result<Vec<u8>, Error> {
        let nonce = self.decryption_nonce.get();
        self.decrypt_helper(&nonce, &message.ciphertext)
    }

    fn decrypt_helper(&self, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(self.decryption_key());
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| Error::Decryption)?;

        Ok(plaintext)
    }

    fn get_check_code_info(
        app_info: &str,
        role: Role,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> String {
        let partial_info = format!("{app_info}_CHECKCODE");
        Self::construct_info_string(&partial_info, role, our_public_key, their_public_key)
    }

    fn get_encryption_key_info(
        app_info: &str,
        role: Role,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> String {
        let partial_info = match role {
            Role::Initiator => format!("{app_info}_ENCKEY_S"),
            Role::Recipient => format!("{app_info}_ENCKEY_G"),
        };
        Self::construct_info_string(&partial_info, role, our_public_key, their_public_key)
    }

    fn get_decryption_key_info(
        app_info: &str,
        role: Role,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> String {
        // The decryption key for G is the encryption key for S and vice versa.
        let partial_info = match role {
            Role::Initiator => format!("{app_info}_ENCKEY_G"),
            Role::Recipient => format!("{app_info}_ENCKEY_S"),
        };
        Self::construct_info_string(&partial_info, role, our_public_key, their_public_key)
    }

    fn construct_info_string(
        partial_info: &str,
        role: Role,
        our_public_key: Curve25519PublicKey,
        their_public_key: Curve25519PublicKey,
    ) -> String {
        match role {
            Role::Recipient => {
                // we are Device G. Gp = our_public_key, Sp = their_public_key
                format!(
                    "{partial_info}|{}|{}",
                    our_public_key.to_base64(),
                    their_public_key.to_base64(),
                )
            }
            Role::Initiator => {
                // we are Device S. Gp = their_public_key, Sp = our_public_key
                format!(
                    "{partial_info}|{}|{}",
                    their_public_key.to_base64(),
                    our_public_key.to_base64(),
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use insta::assert_debug_snapshot;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn channel_creation() {
        let plaintext = b"It's a secret to everybody";

        let alice = Ecies::new();
        let bob = Ecies::new();

        let OutboundCreationResult { ecies: mut alice, message } = alice
            .establish_outbound_channel(bob.public_key(), plaintext)
            .expect("We should be able to create an outbound channel");

        let InboundCreationResult { ecies: mut bob, message } = bob
            .establish_inbound_channel(&message)
            .expect("We should be able to create an inbound channel");

        assert_eq!(
            message, plaintext,
            "The decrypted plaintext should match our initial plaintext"
        );
        assert_eq!(alice.check_code(), bob.check_code());
        assert_eq!(alice.check_code().to_digit(), bob.check_code().to_digit());

        let message = bob.encrypt(b"Another plaintext");

        let decrypted =
            alice.decrypt(&message).expect("We should be able to decrypt the second message");

        assert_eq!(decrypted, b"Another plaintext");
    }

    #[test]
    fn invalid_check_code() {
        let plaintext = b"It's a secret to everybody";

        let alice = Ecies::new();
        let bob = Ecies::new();
        let malory = Ecies::new();

        let OutboundCreationResult { mut message, .. } = alice
            .establish_outbound_channel(bob.public_key(), plaintext)
            .expect("We should be able to create an outbound channel");

        message.public_key = malory.public_key();

        bob.establish_inbound_channel(&message).expect_err(
            "The decryption should fail since Malory inserted the \
             wrong public key into the message",
        );
    }

    #[test]
    fn nonce() {
        let mut nonce = EciesNonce::new();

        assert_eq!(nonce.inner, 0, "The nonce should start the counter from 0");

        let first = nonce.get();

        assert_eq!(
            nonce.inner, 1,
            "After the first nonce is returned, the counter should have been incremented"
        );

        #[allow(deprecated)]
        let first = first.as_slice();
        assert_eq!(first, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let second = nonce.get();

        assert_eq!(
            nonce.inner, 2,
            "After the first nonce is returned, the counter should have been incremented"
        );

        #[allow(deprecated)]
        let second = second.as_slice();
        assert_eq!(second, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]
    fn check_code() {
        let check_code = CheckCode { bytes: [0x0, 0x0] };
        let digit = check_code.to_digit();
        assert_eq!(digit, 0, "Two zero bytes should generate a 0 digit");
        assert_eq!(
            check_code.as_bytes(),
            &[0x0, 0x0],
            "CheckCode::as_bytes() should return the exact bytes we generated."
        );

        let check_code = CheckCode { bytes: [0x9, 0x9] };
        let digit = check_code.to_digit();
        assert_eq!(
            check_code.as_bytes(),
            &[0x9, 0x9],
            "CheckCode::as_bytes() should return the exact bytes we generated."
        );
        assert_eq!(digit, 99);

        let check_code = CheckCode { bytes: [0xff, 0xff] };
        let digit = check_code.to_digit();
        assert_eq!(
            check_code.as_bytes(),
            &[0xff, 0xff],
            "CheckCode::as_bytes() should return the exact bytes we generated."
        );
        assert_eq!(digit, 55, "u8::MAX should generate 55");
    }

    #[test]
    fn test_info_construction() {
        use crate::types::Curve25519Keypair;

        let app_info = "foobar";
        let our_public_key = Curve25519Keypair::new().public_key;
        let their_public_key = Curve25519Keypair::new().public_key;

        let check_code_info1 = EstablishedEcies::get_check_code_info(
            app_info,
            Role::Initiator,
            our_public_key,
            their_public_key,
        );
        assert_eq!(
            check_code_info1,
            format!("foobar_CHECKCODE|{their_public_key}|{our_public_key}")
        );

        let check_code_info2 = EstablishedEcies::get_check_code_info(
            app_info,
            Role::Recipient,
            our_public_key,
            their_public_key,
        );
        assert_eq!(
            check_code_info2,
            format!("foobar_CHECKCODE|{our_public_key}|{their_public_key}")
        );
    }

    #[test]
    fn snapshot_debug() {
        let key = Curve25519PublicKey::from_bytes([0; 32]);

        let alice = Ecies::new();
        let bob = Ecies::new();

        let OutboundCreationResult { mut ecies, .. } = alice
            .establish_outbound_channel(bob.public_key(), b"")
            .expect("We should be able to establish a Ecies channel");

        ecies.our_public_key = key;
        ecies.their_public_key = key;
        ecies.check_code = CheckCode { bytes: [0, 1] };

        assert_debug_snapshot!(ecies);
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
