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

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, BlockModeError, Cbc};
use hmac::{digest::MacError, Hmac, Mac as MacT};
use key::CipherKeys;
use sha2::Sha256;
use thiserror::Error;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

pub struct Mac([u8; 32]);

impl Mac {
    pub const TRUNCATED_LEN: usize = 8;

    pub fn truncate(&self) -> [u8; Self::TRUNCATED_LEN] {
        let mut truncated = [0u8; Self::TRUNCATED_LEN];
        truncated.copy_from_slice(&self.0[0..Self::TRUNCATED_LEN]);

        truncated
    }
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Failed decrypting, invalid ciphertext: {0}")]
    InvalidCiphertext(#[from] BlockModeError),
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

    pub fn new_megolm(&key: &[u8; 128]) -> Self {
        let keys = CipherKeys::new_megolm(&key);

        Self { keys }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn new_pickle(key: &[u8]) -> Self {
        let keys = CipherKeys::new_pickle(key);

        Self { keys }
    }

    fn get_cipher(&self) -> Aes256Cbc {
        Aes256Cbc::new_fix(self.keys.aes_key(), self.keys.iv())
    }

    fn get_hmac(&self) -> HmacSha256 {
        // We don't use HmacSha256::new() here because it expects a 64-byte
        // large HMAC key while the Olm spec defines a 32-byte one instead.
        //
        // https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#version-1
        HmacSha256::new_from_slice(self.keys.mac_key()).expect("Invalid HMAC key size")
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.get_cipher();
        cipher.encrypt_vec(plaintext)
    }

    pub fn mac(&self, message: &[u8]) -> Mac {
        let mut hmac = self.get_hmac();
        hmac.update(message);

        let mac_bytes = hmac.finalize().into_bytes();

        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_bytes);

        Mac(mac)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BlockModeError> {
        let cipher = self.get_cipher();
        cipher.decrypt_vec(ciphertext)
    }

    pub fn decrypt_pickle(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if ciphertext.len() < Mac::TRUNCATED_LEN + 1 {
            Err(DecryptionError::MacMissing)
        } else {
            let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - Mac::TRUNCATED_LEN);
            self.verify_mac(ciphertext, mac)?;

            Ok(self.decrypt(ciphertext)?)
        }
    }

    pub fn encrypt_pickle(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = self.encrypt(plaintext);
        let mac = self.mac(&ciphertext);

        ciphertext.extend(mac.truncate());

        ciphertext
    }

    pub fn verify_mac(&self, message: &[u8], tag: &[u8]) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(message);
        hmac.verify_truncated_left(tag)
    }
}
