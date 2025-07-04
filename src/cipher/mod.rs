// Copyright 2021 The Matrix.org Foundation C.I.C.
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

pub(crate) mod key;

use aes::{
    Aes256,
    cipher::{
        BlockDecryptMut, BlockEncryptMut, KeyIvInit,
        block_padding::{Pkcs7, UnpadError},
    },
};
use hmac::{Hmac, Mac as MacT, digest::MacError};
use key::CipherKeys;
use sha2::Sha256;
use thiserror::Error;

pub(crate) type Aes256CbcEnc = cbc::Encryptor<Aes256>;
pub(crate) type Aes256CbcDec = cbc::Decryptor<Aes256>;
pub(crate) type HmacSha256 = Hmac<Sha256>;

/// The message authentication code of a ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mac(pub(crate) [u8; Self::LENGTH]);

impl Mac {
    /// The expected length of the message authentication code (MAC).
    pub const LENGTH: usize = 32;
    /// The expected length of the message authentication code (MAC) if
    /// truncation is applied.
    pub const TRUNCATED_LEN: usize = 8;

    /// Truncates and converts the [`Mac`] into a byte array.
    pub fn truncate(&self) -> [u8; Self::TRUNCATED_LEN] {
        let mut truncated = [0u8; Self::TRUNCATED_LEN];
        truncated.copy_from_slice(&self.0[0..Self::TRUNCATED_LEN]);

        truncated
    }

    /// Return the [`Mac`] as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MessageMac {
    Truncated([u8; Mac::TRUNCATED_LEN]),
    Full(Mac),
}

impl MessageMac {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MessageMac::Truncated(m) => m.as_ref(),
            MessageMac::Full(m) => m.as_bytes(),
        }
    }
}

impl From<Mac> for MessageMac {
    fn from(m: Mac) -> Self {
        Self::Full(m)
    }
}

impl From<[u8; Mac::TRUNCATED_LEN]> for MessageMac {
    fn from(m: [u8; Mac::TRUNCATED_LEN]) -> Self {
        Self::Truncated(m)
    }
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Failed decrypting, invalid padding")]
    InvalidPadding(#[from] UnpadError),
    #[error("The MAC of the ciphertext didn't pass validation {0}")]
    Mac(#[from] MacError),
    #[error("The ciphertext didn't contain a valid MAC")]
    MacMissing,
}

/// A cipher used for encrypting and decrypting messages.
pub struct Cipher {
    keys: CipherKeys,
}

impl Cipher {
    /// Creates a new [`Cipher`] from the given 32-byte raw key.
    ///
    /// The key is deterministically expanded into a 32-byte AES key, a 32-byte
    /// MAC key, and a 16-byte initialization vector (IV) using HKDF, with the
    /// byte string "OLM_KEYS" used as the info during key derivation.
    ///
    /// This key derivation format is typically used for generating individual
    /// message keys in the Olm double ratchet.
    pub fn new(key: &[u8; 32]) -> Self {
        let keys = CipherKeys::new(key);

        Self { keys }
    }

    /// Creates a new [`Cipher`] from the given 128-byte raw key.
    ///
    /// The key is deterministically expanded into a 32-byte AES key, a 32-byte
    /// MAC key, and a 16-byte initialization vector (IV) using HKDF, with
    /// the byte string "MEGOLM_KEYS" used as the info during key
    /// derivation.
    ///
    /// This key derivation format is typically used for generating individual
    /// message keys in the Megolm ratchet.
    pub fn new_megolm(&key: &[u8; 128]) -> Self {
        let keys = CipherKeys::new_megolm(&key);

        Self { keys }
    }

    /// Creates a new [`Cipher`] from the given raw key. The key is expected to
    /// be 32 bytes in length, but we expect an unsized slice for
    /// compatibility with the libolm API.
    ///
    /// The key is deterministically expanded into a 32-byte AES key, a 32-byte
    /// MAC key, and a 16-byte initialization vector (IV) using HKDF, with
    /// the byte string "Pickle" used as the info during key derivation.
    ///
    /// This key derivation format is typically used for libolm-compatible
    /// encrypted pickle formats.
    pub fn new_pickle(key: &[u8]) -> Self {
        let keys = CipherKeys::new_pickle(key);

        Self { keys }
    }

    fn get_hmac(&self) -> HmacSha256 {
        // We don't use HmacSha256::new() here because it expects a 64-byte
        // large HMAC key while the Olm spec defines a 32-byte one instead.
        //
        // https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#version-1
        #[allow(clippy::expect_used)]
        HmacSha256::new_from_slice(self.keys.mac_key())
            .expect("We should be able to create a HmacSha256 from a 32 byte key")
    }

    /// Encrypts the given plaintext using this [`Cipher`] and returns the
    /// ciphertext.
    ///
    /// **Warning**: This is a low-level function and does not provide
    /// authentication for the ciphertext. You must call [`Cipher::mac()`]
    /// separately to generate the message authentication code (MAC).
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256CbcEnc::new(self.keys.aes_key(), self.keys.iv());
        cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    /// Generates a message authentication code (MAC) for the given ciphertext.
    ///
    /// **Warning**: This is a low-level function and must be called after the
    /// [`Cipher::encrypt`] method. The ciphertext produced by
    /// [`Cipher::encrypt`] must be passed as the argument to this method.
    pub fn mac(&self, message: &[u8]) -> Mac {
        let mut hmac = self.get_hmac();
        hmac.update(message);

        let mac_bytes = hmac.finalize().into_bytes();

        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_bytes);

        Mac(mac)
    }

    /// Decrypts the provided `ciphertext` using this [`Cipher`].
    ///
    /// **Warning**: This is a low-level function. Before calling this, you must
    /// call [`Cipher::verify_mac()`] or [`Cipher::verify_truncated_mac()`]
    /// to ensure the integrity of the ciphertext.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
        let cipher = Aes256CbcDec::new(self.keys.aes_key(), self.keys.iv());
        cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
    }

    /// Verifies that the provided message authentication code (MAC) correctly
    /// authenticates the given message.
    ///
    /// **Warning**: This is a low-level function and must be called before
    /// invoking the [`Cipher::decrypt()`] method.
    #[cfg(not(fuzzing))]
    pub fn verify_mac(&self, message: &[u8], tag: &Mac) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(message);
        hmac.verify_slice(tag.as_bytes())
    }

    /// Verifies that the provided truncated message authentication code (MAC)
    /// correctly authenticates the given message.
    ///
    /// **Warning**: This is a low-level function and must be called before
    /// invoking the [`Cipher::decrypt()`] method.
    #[cfg(not(fuzzing))]
    pub fn verify_truncated_mac(&self, message: &[u8], tag: &[u8]) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(message);
        hmac.verify_truncated_left(tag)
    }

    /// A [`Cipher::verify_mac()`] method that always succeeds.
    ///
    /// **Warning**: If you're seeing this comment and are not fuzzing the
    /// library, the library is operating with an insecure build-time
    /// configuration.
    ///
    /// This mode is intended only for fuzzing vodozemac, as MAC verification
    /// typically filters out many inputs early in the process.
    #[cfg(fuzzing)]
    pub fn verify_mac(&self, _: &[u8], _: &Mac) -> Result<(), MacError> {
        Ok(())
    }

    /// A [`Cipher::verify_truncated_mac()`] method that always succeeds.
    ///
    /// **Warning**: If you're seeing this comment and are not fuzzing the
    /// library, the library is operating with an insecure build-time
    /// configuration.
    ///
    /// This mode is intended only for fuzzing vodozemac, as MAC verification
    /// typically filters out many inputs early in the process.
    #[cfg(fuzzing)]
    pub fn verify_truncated_mac(&self, _: &[u8], _: &[u8]) -> Result<(), MacError> {
        Ok(())
    }

    /// Encrypts the given plaintext using this [`Cipher`] and returns the
    /// ciphertext.
    ///
    /// This method authenticates the ciphertext and appends the truncated
    /// message authentication tag to it.
    ///
    /// This follows the encryption method used by the libolm pickle format.
    pub fn encrypt_pickle(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = self.encrypt(plaintext);
        let mac = self.mac(&ciphertext);

        ciphertext.extend(mac.truncate());

        ciphertext
    }

    /// Decrypts the provided `ciphertext` using this [`Cipher`].
    ///
    /// This function expects the message authentication code (MAC), truncated
    /// to 8 bytes, to be concatenated with the ciphertext. It verifies the
    /// MAC before decrypting the ciphertext.
    ///
    /// This follows the encryption method used by the libolm pickle format.
    pub fn decrypt_pickle(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.len() < Mac::TRUNCATED_LEN + 1 {
            Err(DecryptionError::MacMissing)
        } else {
            let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - Mac::TRUNCATED_LEN);
            self.verify_truncated_mac(ciphertext, mac)?;

            Ok(self.decrypt(ciphertext)?)
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::{Cipher, Mac};
    use crate::cipher::DecryptionError;

    #[test]
    fn decrypt_pickle_mac_missing() {
        let cipher = Cipher::new(&[1u8; 32]);
        assert_matches!(
            cipher.decrypt_pickle(&[2u8; Mac::TRUNCATED_LEN]),
            Err(DecryptionError::MacMissing)
        );

        assert_matches!(
            cipher.decrypt_pickle(&[0u8; Mac::TRUNCATED_LEN + 1]),
            Err(DecryptionError::Mac(_))
        );
    }
}
