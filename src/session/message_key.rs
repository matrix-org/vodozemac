use super::{messages::OlmMessage, DecodedMessage, RatchetPublicKey};
use crate::cipher::Cipher;

pub(super) struct MessageKey {
    key: [u8; 32],
    ratchet_key: RatchetPublicKey,
    index: u64,
}

pub(super) struct RemoteMessageKey {
    pub key: [u8; 32],
    pub index: u64,
}

impl MessageKey {
    pub fn new(key: [u8; 32], ratchet_key: RatchetPublicKey, index: u64) -> Self {
        Self { key, ratchet_key, index }
    }

    fn construct_message(self, ciphertext: Vec<u8>) -> OlmMessage {
        OlmMessage::from_parts(self.ratchet_key, self.index, ciphertext)
    }

    pub fn encrypt(self, plaintext: &[u8]) -> OlmMessage {
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

    pub fn decrypt(self, message: &OlmMessage, decoded_message: &DecodedMessage) -> Vec<u8> {
        let cipher = Cipher::new(&self.key);

        cipher.verify_mac(message.as_payload_bytes(), &decoded_message.mac).expect("Invalid MAC");
        cipher.decrypt(&decoded_message.ciphertext).expect("Couldn't decrypt")
    }
}
