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

mod key;

use aes::{
    cipher::{
        block_padding::{Pkcs7, UnpadError},
        BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    },
    Aes256,
};
use hmac::{digest::MacError, Hmac, Mac as MacT};
use sha2::Sha256;
use thiserror::Error;

use crate::{cipher::key::CipherKeys, Curve25519PublicKey};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mac(pub(crate) [u8; Self::LENGTH]);

impl Mac {
    pub const LENGTH: usize = 32;
    pub const TRUNCATED_LEN: usize = 8;

    pub fn truncate(&self) -> [u8; Self::TRUNCATED_LEN] {
        let mut truncated = [0u8; Self::TRUNCATED_LEN];
        truncated.copy_from_slice(&self.0[0..Self::TRUNCATED_LEN]);

        truncated
    }

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

#[cfg(feature = "interolm")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterolmMessageMac(pub(crate) [u8; Mac::TRUNCATED_LEN]);

#[cfg(feature = "interolm")]
impl InterolmMessageMac {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "interolm")]
impl From<Mac> for InterolmMessageMac {
    fn from(m: Mac) -> Self {
        Self(m.truncate())
    }
}

#[cfg(feature = "interolm")]
impl From<[u8; Mac::TRUNCATED_LEN]> for InterolmMessageMac {
    fn from(m: [u8; Mac::TRUNCATED_LEN]) -> Self {
        Self(m)
    }
}

#[cfg(feature = "interolm")]
impl From<InterolmMessageMac> for MessageMac {
    fn from(value: InterolmMessageMac) -> Self {
        Self::Truncated(value.0)
    }
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Failed decrypting, invalid padding")]
    InvalidPadding(#[from] UnpadError),
    #[error("The MAC of the ciphertext didn't pass validation {0}")]
    Mac(#[from] MacError),
    #[allow(dead_code)]
    #[error("The ciphertext didn't contain a valid MAC")]
    MacMissing,
}

pub struct Cipher {
    keys: CipherKeys,
}

impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let keys = CipherKeys::new(key);

        Self { keys }
    }

    #[cfg(feature = "interolm")]
    pub fn new_interolm(key: &[u8; 32]) -> Self {
        let keys = CipherKeys::new_interolm(key);

        Self { keys }
    }

    pub fn new_megolm(&key: &[u8; 128]) -> Self {
        let keys = CipherKeys::new_megolm(&key);

        Self { keys }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn new_pickle(key: &[u8]) -> Self {
        let keys = CipherKeys::new_pickle(key);

        Self { keys }
    }

    fn get_hmac(&self) -> HmacSha256 {
        // We don't use HmacSha256::new() here because it expects a 64-byte
        // HMAC key while the Olm spec uses a 32-byte one instead.
        //
        // https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#version-1
        HmacSha256::new_from_slice(self.keys.mac_key()).expect("Invalid HMAC key size")
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256CbcEnc::new(self.keys.aes_key(), self.keys.iv());
        cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    pub fn mac(&self, message: &[u8]) -> Mac {
        let mut hmac = self.get_hmac();
        hmac.update(message);

        let mac = hmac.finalize().into_bytes().into();

        Mac(mac)
    }

    pub fn mac_interolm(
        &self,
        sender_identity: Curve25519PublicKey,
        receiver_identity: Curve25519PublicKey,
        message: &[u8],
    ) -> Mac {
        let mut hmac = self.get_hmac();

        hmac.update(&sender_identity.to_interolm_bytes());
        hmac.update(&receiver_identity.to_interolm_bytes());
        hmac.update(message);

        let mac = hmac.finalize().into_bytes().into();

        Mac(mac)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
        let cipher = Aes256CbcDec::new(self.keys.aes_key(), self.keys.iv());
        cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
    }

    pub fn decrypt_pickle(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.len() < Mac::TRUNCATED_LEN + 1 {
            Err(DecryptionError::MacMissing)
        } else {
            let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - Mac::TRUNCATED_LEN);
            self.verify_truncated_mac(ciphertext, mac)?;

            Ok(self.decrypt(ciphertext)?)
        }
    }

    pub fn encrypt_pickle(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = self.encrypt(plaintext);
        let mac = self.mac(&ciphertext);

        ciphertext.extend(mac.truncate());

        ciphertext
    }

    #[cfg(not(fuzzing))]
    pub fn verify_mac(&self, message: &[u8], tag: &Mac) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(message);
        hmac.verify_slice(tag.as_bytes())
    }

    #[cfg(not(fuzzing))]
    pub fn verify_truncated_mac(&self, message: &[u8], tag: &[u8]) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(message);
        hmac.verify_truncated_left(tag)
    }

    #[cfg(not(fuzzing))]
    pub fn verify_interolm_mac(
        &self,
        message: &[u8],
        sender_identity: Curve25519PublicKey,
        receiver_identity: Curve25519PublicKey,
        tag: &[u8],
    ) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(&sender_identity.to_interolm_bytes());
        hmac.update(&receiver_identity.to_interolm_bytes());
        hmac.update(message);
        hmac.verify_truncated_left(tag)
    }

    /// A verify_mac method that always succeeds.
    ///
    /// Useful if we're fuzzing vodozemac, since MAC verification discards a lot
    /// of inputs right away.
    #[cfg(fuzzing)]
    pub fn verify_mac(&self, _: &[u8], _: &Mac) -> Result<(), MacError> {
        Ok(())
    }

    #[cfg(fuzzing)]
    pub fn verify_truncated_mac(&self, _: &[u8], _: &[u8]) -> Result<(), MacError> {
        Ok(())
    }

    #[cfg(fuzzing)]
    pub fn verify_interolm_mac(
        &self,
        _: &[u8],
        _: Curve25519PublicKey,
        _: Curve25519PublicKey,
        _: &[u8],
    ) -> Result<(), MacError> {
        Ok(())
    }
}
