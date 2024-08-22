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

//! ☣️  Compat support for Olm's PkEncryption and PkDecryption
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
        Aes256CbcDec, Aes256CbcEnc, HmacSha256,
    },
    Curve25519PublicKey, Curve25519SecretKey, KeyError,
};

const MAC_LENGTH: usize = 8;

pub struct PkDecryption {
    key: Curve25519SecretKey,
    public_key: Curve25519PublicKey,
}

impl PkDecryption {
    /// Create a new random [`PkDecryption`] object.
    ///
    /// This will create a new random [`Curve25519SecretKey`] which is used as
    /// the long-term
    pub fn new() -> Self {
        let key = Curve25519SecretKey::new();
        let public_key = Curve25519PublicKey::from(&key);

        Self { key, public_key }
    }

    /// Get the [`Curve25519PublicKey`] which is
    pub const fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }

    /// Decrypt a [`Message`] which was encrypted for this [`PkDecryption`]
    /// object.
    pub fn decrypt(&self, message: &Message) -> Result<Vec<u8>, Error> {
        let shared_secret = self.key.diffie_hellman(&message.ephemeral_key);

        let expanded_keys = ExpandedKeys::new_helper(shared_secret.as_bytes(), b"");
        let cipher_keys = CipherKeys::from_expanded_keys(expanded_keys);

        let hmac = HmacSha256::new_from_slice(cipher_keys.mac_key())
            .expect("We should be able to create a Hmac object from a 32 byte key");

        // This is a know issue, we check the MAC of an empty message instead of
        // updating the `hmac` object with the ciphertext bytes.
        hmac.verify_truncated_left(&message.mac)?;

        let cipher = Aes256CbcDec::new(cipher_keys.aes_key(), cipher_keys.iv());
        let decrypted = cipher.decrypt_padded_vec_mut::<Pkcs7>(&message.ciphertext)?;

        Ok(decrypted)
    }

    /// Create a [`PkDecryption`] object from a slice of bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let key = Curve25519SecretKey::from_slice(bytes);
        let public_key = Curve25519PublicKey::from(&key);

        Self { key, public_key }
    }

    /// Export this [`PkDecryption`] object to a slice of bytes.
    pub fn to_bytes(&self) -> Box<[u8; 32]> {
        self.key.to_bytes()
    }
}

impl Default for PkDecryption {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PkEncryption {
    public_key: Curve25519PublicKey,
}

impl PkEncryption {
    pub const fn from_key(public_key: Curve25519PublicKey) -> Self {
        Self { public_key }
    }

    pub fn encrypt(&self, message: &[u8]) -> Message {
        let ephemeral_key = Curve25519SecretKey::new();
        let shared_secret = ephemeral_key.diffie_hellman(&self.public_key);

        let expanded_keys = ExpandedKeys::new_helper(shared_secret.as_bytes(), b"");
        let cipher_keys = CipherKeys::from_expanded_keys(expanded_keys);

        let cipher = Aes256CbcEnc::new(cipher_keys.aes_key(), cipher_keys.iv());
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(message);

        let hmac = HmacSha256::new_from_slice(cipher_keys.mac_key())
            .expect("We should be able to create a Hmac object from a 32 byte key");

        // This is a know issue, we create a MAC of an empty message instead of
        // updating the `hmac` object with the ciphertext bytes.
        let mut mac = hmac.finalize().into_bytes().to_vec();
        mac.truncate(MAC_LENGTH);

        Message { ciphertext, mac, ephemeral_key: Curve25519PublicKey::from(&ephemeral_key) }
    }
}

impl From<&PkDecryption> for PkEncryption {
    fn from(value: &PkDecryption) -> Self {
        Self::from(value.public_key())
    }
}

impl From<Curve25519PublicKey> for PkEncryption {
    fn from(public_key: Curve25519PublicKey) -> Self {
        Self { public_key }
    }
}

#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error(transparent)]
    Base64(#[from] crate::Base64DecodeError),
    #[error(transparent)]
    Key(#[from] KeyError),
}

#[derive(Debug)]
pub struct Message {
    pub ciphertext: Vec<u8>,
    pub mac: Vec<u8>,
    pub ephemeral_key: Curve25519PublicKey,
}

impl Message {
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

/// Error type describing the failure cases the Pk decryption step can have.
#[derive(Debug, Error)]
pub enum Error {
    /// The message has invalid PKCS7 padding.
    #[error("Failed decrypting, invalid padding: {0}")]
    InvalidPadding(#[from] UnpadError),
    /// The message failed to be authenticated.
    #[error("The MAC of the ciphertext didn't pass validation {0}")]
    Mac(#[from] MacError),
    /// The message's Curve25519 key failed to be decoded.
    #[error("The message's ephemeral Curve25519 key could not been decoded: {0}")]
    InvalidCurveKey(#[from] KeyError),
    /// The decrypted message should contain a backed up room key, but the
    /// plaintext isn't valid JSON.
    #[error("The decrypted message isn't valid JSON: {0}")]
    Json(#[from] serde_json::error::Error),
}

#[cfg(test)]
mod tests {
    use olm_rs::pk::{OlmPkDecryption, OlmPkEncryption, PkMessage};

    use super::{Message, MessageDecodeError, PkDecryption, PkEncryption};
    use crate::{base64_encode, Curve25519PublicKey};

    // Conversion from the libolm type to the vodozemac type. To make some tests
    // easier on the eyes.
    impl TryFrom<PkMessage> for Message {
        type Error = MessageDecodeError;

        fn try_from(value: PkMessage) -> Result<Self, Self::Error> {
            Self::from_base64(&value.ciphertext, &value.mac, &value.ephemeral_key)
        }
    }

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
        let encrypted = encrypted.try_into().unwrap();

        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(message.as_bytes(), decrypted);
    }

    #[test]
    fn encrypt_for_libolm_pk_decryption() {
        let decryptor = OlmPkDecryption::new();
        let public_key = Curve25519PublicKey::from_base64(decryptor.public_key()).unwrap();
        let encryptor = PkEncryption::from_key(public_key);

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message.as_ref());
        let encrypted = encrypted.into();

        let decrypted = decryptor.decrypt(encrypted).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn encryption_roundtrip() {
        let decryptor = PkDecryption::new();
        let public_key = decryptor.public_key();
        let encryptor = PkEncryption::from_key(public_key);

        let message = "It's a secret to everybody";

        let encrypted = encryptor.encrypt(message.as_ref());
        let decrypted = decryptor.decrypt(&encrypted).unwrap();

        assert_eq!(message.as_ref(), decrypted);
    }

    #[test]
    fn from_bytes() {
        let decryption = PkDecryption::default();
        let bytes = decryption.to_bytes();

        let restored = PkDecryption::from_bytes(&bytes);

        assert_eq!(
            decryption.public_key(),
            restored.public_key(),
            "The public keys of the restored and original PK decryption should match"
        );
    }
}
