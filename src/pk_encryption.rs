// Copyright 2023 The Matrix.org Foundation C.I.C.
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

//! ☣️  Compat support for libolm's PkEncryption and PkDecryption
//!
//! This implements the `m.megolm_backup.v1.curve25519-aes-sha2` described in
//! the Matrix [spec]. This is a hybrid encryption scheme utilizing Curve25519
//! and AES-CBC. X25519 ECDH is performed between an ephemeral key pair and a
//! long-lived backup key pair to establish a shared secret, from which
//! symmetric encryption and message authentication (MAC) keys are derived.
//!
//! **WARNING**: Please note the algorithm contains a critical flaw and does not
//! provide authentication of the ciphertext.
//!
//! # Examples
//!
//! ```
//! use anyhow::Result;
//! use vodozemac::pk_encryption::{PkDecryption, PkEncryption};
//!
//! fn main() -> Result<()> {
//!     let plaintext = b"It's a secret to everybody";
//!
//!     let decryption = PkDecryption::new();
//!     let encryption = PkEncryption::from_key(decryption.public_key());
//!
//!     let message = encryption.encrypt(plaintext);
//!     let decrypted = decryption.decrypt(&message)?;
//!
//!     assert_eq!(decrypted.as_slice(), plaintext);
//!
//!     Ok(())
//! }
//! ```
//!
//! [spec]: https://spec.matrix.org/v1.11/client-server-api/#backup-algorithm-mmegolm_backupv1curve25519-aes-sha2

use aes::cipher::{
    block_padding::{Pkcs7, UnpadError},
    BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _,
};
use hmac::{digest::MacError, Mac as _};
use thiserror::Error;

use crate::{
    base64_decode,
    cipher::{
        key::{CipherKeys, ExpandedKeys},
        Aes256CbcDec, Aes256CbcEnc, HmacSha256, Mac,
    },
    Curve25519PublicKey, Curve25519SecretKey, KeyError,
};

/// An error type describing failures which can happen during the decryption
/// step.
#[derive(Debug, Error)]
pub enum Error {
    /// The message has invalid [Pkcs7] padding.
    #[error("failed to decrypt, invalid padding: {0}")]
    InvalidPadding(#[from] UnpadError),
    /// The message failed to be authenticated.
    #[error("the MAC of the ciphertext didn't pass validation: {0}")]
    Mac(#[from] MacError),
}

/// An error type describing failures which can happen during the decoding of an
/// encrypted [`Message`].
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    /// One of the message parts wasn't valid Base64.
    #[error(transparent)]
    Base64(#[from] crate::Base64DecodeError),
    /// The ephemeral Curve25519 key isn't valid.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// A message that was encrypted using a [`PkEncryption`] object.
#[derive(Debug)]
pub struct Message {
    /// The ciphertext of the message.
    pub ciphertext: Vec<u8>,
    /// The message authentication code of the message.
    ///
    /// **WARNING**: As stated in the module description, this does not
    /// authenticate the message.
    pub mac: Vec<u8>,
    /// The ephemeral [`Curve25519PublicKey`] used to derive the individual
    /// message key.
    pub ephemeral_key: Curve25519PublicKey,
}

impl Message {
    /// Attempt to decode a PkEncryption [`Message`] from a Base64-encoded
    /// triplet of ciphertext, MAC, and ephemeral key.
    pub fn from_base64(
        ciphertext: &str,
        mac: &str,
        ephemeral_key: &str,
    ) -> Result<Self, MessageDecodeError> {
        Ok(Self {
            ciphertext: base64_decode(ciphertext)?,
            mac: base64_decode(mac)?,
            ephemeral_key: Curve25519PublicKey::from_base64(ephemeral_key)?,
        })
    }
}

/// The decryption component of the PkEncryption support.
///
/// The public key can be shared with others, allowing them to encrypt messages
/// which can be decrypted using the corresponding private key.
pub struct PkDecryption {
    secret_key: Curve25519SecretKey,
    public_key: Curve25519PublicKey,
}

impl PkDecryption {
    /// Create a new random [`PkDecryption`] object.
    ///
    /// This contains a fresh [`Curve25519SecretKey`] which is used as a
    /// long-term key to derive individual message keys and effectively serves
    /// as the decryption secret.
    pub fn new() -> Self {
        let secret_key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&secret_key);

        Self { secret_key, public_key }
    }

    /// Create a [`PkDecryption`] object from a [`Curve25519SecretKey`] key.
    ///
    /// The [`Curve25519SecretKey`] will be used as the long-term key to derive
    /// individual message keys.
    pub fn from_key(secret_key: Curve25519SecretKey) -> Self {
        let public_key = Curve25519PublicKey::from(&secret_key);
        Self { secret_key, public_key }
    }

    /// Get the [`Curve25519SecretKey`] of this [`PkDecryption`] object.
    ///
    /// If persistence is required, securely serialize and store this key. It
    /// can be used to reconstruct the [`PkDecryption`] object for decrypting
    /// associated messages.
    pub const fn secret_key(&self) -> &Curve25519SecretKey {
        &self.secret_key
    }

    /// Get the associated ephemeral [`Curve25519PublicKey`]. This key can be
    /// used to reconstruct the [`PkEncryption`] object to encrypt messages.
    pub const fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }

    /// Decrypt a [`Message`] which was encrypted for this [`PkDecryption`]
    /// object.
    pub fn decrypt(&self, message: &Message) -> Result<Vec<u8>, Error> {
        let shared_secret = self.secret_key.diffie_hellman(&message.ephemeral_key);

        let expanded_keys = ExpandedKeys::new_helper(shared_secret.as_bytes(), b"");
        let cipher_keys = CipherKeys::from_expanded_keys(expanded_keys);

        let hmac = HmacSha256::new_from_slice(cipher_keys.mac_key())
            .expect("We should be able to create a Hmac object from a 32 byte key");

        // BUG: This is a know issue, we check the MAC of an empty message instead of
        // updating the `hmac` object with the ciphertext bytes.
        hmac.verify_truncated_left(&message.mac)?;

        let cipher = Aes256CbcDec::new(cipher_keys.aes_key(), cipher_keys.iv());
        let decrypted = cipher.decrypt_padded_vec_mut::<Pkcs7>(&message.ciphertext)?;

        Ok(decrypted)
    }
}

impl Default for PkDecryption {
    fn default() -> Self {
        Self::new()
    }
}

/// The encryption component of PkEncryption support.
///
/// This struct can be created from a [`Curve25519PublicKey`] corresponding to
/// a [`PkDecryption`] object, allowing encryption of messages for that object.
pub struct PkEncryption {
    public_key: Curve25519PublicKey,
}

impl PkEncryption {
    /// Create a new [`PkEncryption`] object from a [`Curve25519PublicKey`].
    ///
    /// The public key should be obtained from an existing  [`PkDecryption`]
    /// object.
    pub const fn from_key(public_key: Curve25519PublicKey) -> Self {
        Self { public_key }
    }

    /// Encrypt a message using this [`PkEncryption`] object.
    pub fn encrypt(&self, message: &[u8]) -> Message {
        let ephemeral_key = Curve25519SecretKey::new();
        let shared_secret = ephemeral_key.diffie_hellman(&self.public_key);

        let expanded_keys = ExpandedKeys::new_helper(shared_secret.as_bytes(), b"");
        let cipher_keys = CipherKeys::from_expanded_keys(expanded_keys);

        let cipher = Aes256CbcEnc::new(cipher_keys.aes_key(), cipher_keys.iv());
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(message);

        let hmac = HmacSha256::new_from_slice(cipher_keys.mac_key())
            .expect("We should be able to create a Hmac object from a 32 byte key");

        // BUG: This is a know issue, we create a MAC of an empty message instead of
        // updating the `hmac` object with the ciphertext bytes.
        let mut mac = hmac.finalize().into_bytes().to_vec();
        mac.truncate(Mac::TRUNCATED_LEN);

        Message { ciphertext, mac, ephemeral_key: Curve25519PublicKey::from(&ephemeral_key) }
    }
}

impl From<&PkDecryption> for PkEncryption {
    fn from(value: &PkDecryption) -> Self {
        Self::from_key(value.public_key())
    }
}

impl From<Curve25519PublicKey> for PkEncryption {
    fn from(public_key: Curve25519PublicKey) -> Self {
        Self { public_key }
    }
}

#[cfg(test)]
mod tests {
    use olm_rs::pk::{OlmPkDecryption, OlmPkEncryption, PkMessage};

    use super::{Message, MessageDecodeError, PkDecryption, PkEncryption};
    use crate::{base64_encode, Curve25519PublicKey, Curve25519SecretKey};

    /// Conversion from the libolm type to the vodozemac type. To make some
    /// tests easier on the eyes.
    impl TryFrom<PkMessage> for Message {
        type Error = MessageDecodeError;

        fn try_from(value: PkMessage) -> Result<Self, Self::Error> {
            Self::from_base64(&value.ciphertext, &value.mac, &value.ephemeral_key)
        }
    }

    /// Conversion from the vodozemac type to the libolm type, in a similar
    /// manner to the above [TryFrom] implementation.
    impl From<Message> for PkMessage {
        fn from(val: Message) -> Self {
            PkMessage {
                ciphertext: base64_encode(val.ciphertext),
                mac: base64_encode(val.mac),
                ephemeral_key: val.ephemeral_key.to_base64(),
            }
        }
    }

    #[test]
    fn decrypt_libolm_encrypted_message() {
        let decryptor = PkDecryption::new();
        let public_key = decryptor.public_key();
        let encryptor = OlmPkEncryption::new(&public_key.to_base64());

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message);
        let encrypted =
            encrypted.try_into().expect("We should be able to decode a message libolm created");

        let decrypted = decryptor
            .decrypt(&encrypted)
            .expect("We should be able to decrypt a message libolm encrypted");

        assert_eq!(
            message.as_bytes(),
            decrypted,
            "The plaintext should match the decrypted message"
        );
    }

    #[test]
    fn encrypt_for_libolm_pk_decryption() {
        let decryptor = OlmPkDecryption::new();
        let public_key = Curve25519PublicKey::from_base64(decryptor.public_key())
            .expect("libolm should provide us with a valid Curve25519 public key");
        let encryptor = PkEncryption::from_key(public_key);

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message.as_ref());
        let encrypted = encrypted.into();

        let decrypted = decryptor
            .decrypt(encrypted)
            .expect("We should be able to decrypt a message vodozemac encrypted using libolm");

        assert_eq!(message, decrypted, "The plaintext should match the decrypted message");
    }

    #[test]
    fn encryption_roundtrip() {
        let decryptor = PkDecryption::new();
        let public_key = decryptor.public_key();
        let encryptor = PkEncryption::from_key(public_key);

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message.as_ref());
        let decrypted = decryptor
            .decrypt(&encrypted)
            .expect("We should be able to decrypt a message we encrypted");

        assert_eq!(message.as_ref(), decrypted, "The plaintext should match the decrypted message");
    }

    #[test]
    fn from_bytes() {
        let decryption = PkDecryption::default();
        let bytes = decryption.secret_key().to_bytes();

        let secret_key = Curve25519SecretKey::from_slice(&bytes);
        let restored = PkDecryption::from_key(secret_key);

        assert_eq!(
            decryption.public_key(),
            restored.public_key(),
            "The public keys of the restored and original PK decryption should match"
        );
    }
}
