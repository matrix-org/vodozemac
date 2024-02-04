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

use super::{ratchet::RatchetPublicKey, DecryptionError};
use crate::{
    cipher::{Cipher, InterolmMessageMac, Mac},
    olm::{messages::Message, session_config::SessionCreator, InterolmMessage, SessionKeys},
};

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
    pub fn new(key: Box<[u8; 32]>, ratchet_key: RatchetPublicKey, index: u64) -> Self {
        Self { key, ratchet_key, index }
    }

    pub fn encrypt_truncated_mac(self, plaintext: &[u8]) -> Message {
        let cipher = Cipher::new(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message =
            Message::new_truncated_mac(*self.ratchet_key.as_ref(), self.index, ciphertext);

        let mac = cipher.mac(&message.to_mac_bytes());
        message.set_mac(mac);

        message
    }

    pub fn encrypt(self, plaintext: &[u8]) -> Message {
        let cipher = Cipher::new(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message = Message::new(*self.ratchet_key.as_ref(), self.index, ciphertext);

        let mac = cipher.mac(&message.to_mac_bytes());
        message.set_mac(mac);

        message
    }

    #[cfg(feature = "interolm")]
    pub fn encrypt_interolm(
        self,
        session_keys: &SessionKeys,
        session_creator: SessionCreator,
        previous_counter: u32,
        plaintext: &[u8],
    ) -> InterolmMessage {
        let cipher = Cipher::new_interolm(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message = InterolmMessage::new(
            *self.ratchet_key.as_ref(),
            self.index.try_into().expect("Interolm doesn't support encrypting more than 2^32 messages with a single sender chain"),
            previous_counter,
            ciphertext,
        );

        let sender_identity;
        let receiver_identity;

        match session_creator {
            SessionCreator::Us => {
                sender_identity = session_keys.identity_key;
                receiver_identity = session_keys.other_identity_key;
            }
            SessionCreator::Them => {
                sender_identity = session_keys.other_identity_key;
                receiver_identity = session_keys.identity_key;
            }
        };

        let mac = cipher.mac_interolm(sender_identity, receiver_identity, &message.to_mac_bytes());
        message.set_mac(mac);

        message
    }

    /// Get a reference to the message key's key.
    #[cfg(feature = "low-level-api")]
    pub fn key(&self) -> &[u8; 32] {
        self.key.as_ref()
    }

    /// Get the message key's ratchet key.
    #[cfg(feature = "low-level-api")]
    pub fn ratchet_key(&self) -> RatchetPublicKey {
        self.ratchet_key
    }

    /// Get the message key's index.
    #[cfg(feature = "low-level-api")]
    pub fn index(&self) -> u64 {
        self.index
    }
}

impl RemoteMessageKey {
    pub fn new(key: Box<[u8; 32]>, index: u64) -> Self {
        Self { key, index }
    }

    pub fn chain_index(&self) -> u64 {
        self.index
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

    pub fn decrypt_truncated_mac(&self, message: &Message) -> Result<Vec<u8>, DecryptionError> {
        let cipher = Cipher::new(&self.key);

        if let crate::cipher::MessageMac::Truncated(m) = &message.mac {
            cipher.verify_truncated_mac(&message.to_mac_bytes(), m)?;
            Ok(cipher.decrypt(&message.ciphertext)?)
        } else {
            Err(DecryptionError::InvalidMACLength(Mac::TRUNCATED_LEN, Mac::LENGTH))
        }
    }

    #[cfg(feature = "interolm")]
    pub fn decrypt_interolm(
        &self,
        session_keys: &SessionKeys,
        session_creator: SessionCreator,
        message: &InterolmMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        let cipher = Cipher::new_interolm(&self.key);

        let sender_identity;
        let receiver_identity;

        match session_creator {
            SessionCreator::Us => {
                sender_identity = session_keys.other_identity_key;
                receiver_identity = session_keys.identity_key;
            }
            SessionCreator::Them => {
                sender_identity = session_keys.identity_key;
                receiver_identity = session_keys.other_identity_key;
            }
        };

        let InterolmMessageMac(m) = &message.mac;
        cipher.verify_interolm_mac(
            &message.to_mac_bytes(),
            sender_identity,
            receiver_identity,
            m,
        )?;

        Ok(cipher.decrypt(&message.ciphertext)?)
    }
}
