use block_modes::BlockModeError;
use hmac::digest::MacError;
use thiserror::Error;
use zeroize::Zeroize;

use super::ratchet::RatchetPublicKey;
use crate::{
    cipher::{Cipher, Mac},
    messages::InnerMessage,
};

#[derive(Zeroize)]
pub(super) struct MessageKey {
    key: [u8; 32],
    ratchet_key: RatchetPublicKey,
    index: u64,
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[derive(Zeroize)]
pub(super) struct RemoteMessageKey {
    pub key: [u8; 32],
    pub index: u64,
}

impl Drop for RemoteMessageKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

impl MessageKey {
    pub fn new(key: [u8; 32], ratchet_key: RatchetPublicKey, index: u64) -> Self {
        Self { key, ratchet_key, index }
    }

    fn construct_message(self, ciphertext: Vec<u8>) -> InnerMessage {
        InnerMessage::from_parts(self.ratchet_key.as_ref(), self.index, ciphertext)
    }

    pub fn encrypt(self, plaintext: &[u8]) -> InnerMessage {
        let cipher = Cipher::new(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message = self.construct_message(ciphertext);

        let mac = cipher.mac(message.as_payload_bytes());
        message.append_mac(mac);

        message
    }
}

impl RemoteMessageKey {
    pub fn new(key: [u8; 32], index: u64) -> Self {
        Self { key, index }
    }

    pub fn chain_index(&self) -> u64 {
        self.index
    }

    pub fn decrypt(
        &self,
        message: &InnerMessage,
        ciphertext: &[u8],
        mac: [u8; Mac::TRUNCATED_LEN],
    ) -> Result<Vec<u8>, OlmDecryptionError> {
        let cipher = Cipher::new(&self.key);

        cipher.verify_mac(message.as_payload_bytes(), &mac)?;
        Ok(cipher.decrypt(ciphertext)?)
    }
}

#[derive(Error, Debug)]
pub enum OlmDecryptionError {
    #[error("Failed decrypting Olm message, invalid MAC: {}", .0)]
    InvalidMAC(#[from] MacError),
    #[error("Failed decrypting Olm message, invalid ciphertext: {}", .0)]
    InvalidCiphertext(#[from] BlockModeError),
}
