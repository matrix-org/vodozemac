// Copyright 2021 Damir Jelić, Denis Kasak
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

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{DecryptionError, ratchet::RatchetPublicKey};
use crate::{
    cipher::{Cipher, Mac},
    olm::messages::Message,
};

/// A single-use encryption key for per-message encryption.
///
/// This key is used to encrypt a single message in an Olm session.
pub struct MessageKey {
    key: Box<[u8; 32]>,
    ratchet_key: RatchetPublicKey,
    index: u64,
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct RemoteMessageKey {
    pub key: Box<[u8; 32]>,
    pub index: u64,
}

impl Debug for RemoteMessageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { key: _, index } = self;

        f.debug_struct("RemoteMessageKey").field("index", index).finish()
    }
}

impl Drop for RemoteMessageKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

impl MessageKey {
    /// Creates a new [`MessageKey`] from the provided raw 32 bytes, along with
    /// a public ratchet key and index.
    ///
    /// The ratchet key and index will be included in the created [`Message`],
    /// allowing the message recipient to derive the same [`MessageKey`].
    pub const fn new(key: Box<[u8; 32]>, ratchet_key: RatchetPublicKey, index: u64) -> Self {
        Self { key, ratchet_key, index }
    }

    /// Encrypt the given plaintext using this [`MessageKey`].
    ///
    /// This method will authenticate the ciphertext using a 32-byte message
    /// authentication code (MAC). If you need the message authentication code
    /// to be truncated, please take a look at the
    /// [`MessageKey::encrypt_truncated_mac()`] method instead.
    pub fn encrypt(self, plaintext: &[u8]) -> Message {
        let cipher = Cipher::new(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message = Message::new(*self.ratchet_key.as_ref(), self.index, ciphertext);

        let mac = cipher.mac(&message.to_mac_bytes());
        message.set_mac(mac);

        message
    }

    /// Encrypts the provided plaintext using this [`MessageKey`].
    ///
    /// This method authenticates the ciphertext with an 8-byte message
    /// authentication code (MAC). If you require the full, non-truncated
    /// MAC, refer to the [`MessageKey::encrypt()`] method.
    pub fn encrypt_truncated_mac(self, plaintext: &[u8]) -> Message {
        let cipher = Cipher::new(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message =
            Message::new_truncated_mac(*self.ratchet_key.as_ref(), self.index, ciphertext);

        let mac = cipher.mac(&message.to_mac_bytes());
        message.set_mac(mac);

        message
    }

    /// Get a reference to the message key's raw 32-bytes.
    #[cfg(feature = "low-level-api")]
    pub fn key(&self) -> &[u8; 32] {
        self.key.as_ref()
    }

    /// Get the message key's ratchet key.
    #[cfg(feature = "low-level-api")]
    pub const fn ratchet_key(&self) -> RatchetPublicKey {
        self.ratchet_key
    }

    /// Get the message key's index.
    #[cfg(feature = "low-level-api")]
    pub const fn index(&self) -> u64 {
        self.index
    }
}

impl RemoteMessageKey {
    pub const fn new(key: Box<[u8; 32]>, index: u64) -> Self {
        Self { key, index }
    }

    pub const fn chain_index(&self) -> u64 {
        self.index
    }

    pub fn decrypt_truncated_mac(&self, message: &Message) -> Result<Vec<u8>, DecryptionError> {
        let cipher = Cipher::new(&self.key);

        if let crate::cipher::MessageMac::Truncated(m) = &message.mac {
            cipher.verify_truncated_mac(&message.to_mac_bytes(), m)?;
            Ok(cipher.decrypt(&message.ciphertext)?)
        } else {
            Err(DecryptionError::InvalidMACLength(Mac::TRUNCATED_LEN, Mac::LENGTH))
        }
    }

    pub fn decrypt(&self, message: &Message) -> Result<Vec<u8>, DecryptionError> {
        let cipher = Cipher::new(&self.key);

        if let crate::cipher::MessageMac::Full(m) = &message.mac {
            cipher.verify_mac(&message.to_mac_bytes(), m)?;
            Ok(cipher.decrypt(&message.ciphertext)?)
        } else {
            Err(DecryptionError::InvalidMACLength(Mac::LENGTH, Mac::TRUNCATED_LEN))
        }
    }
}

#[cfg(test)]
#[cfg(feature = "low-level-api")]
mod test {
    use super::MessageKey;
    use crate::olm::RatchetPublicKey;

    #[test]
    fn low_level_getters() {
        let key = b"11111111111111111111111111111111";
        let ratchet_key = RatchetPublicKey::from(*b"22222222222222222222222222222222");
        let index: u64 = 3;
        let message_key = MessageKey::new(Box::new(*key), ratchet_key, index);
        assert_eq!(message_key.key(), key);
        assert_eq!(message_key.ratchet_key(), ratchet_key);
        assert_eq!(message_key.index(), index);
    }
}
