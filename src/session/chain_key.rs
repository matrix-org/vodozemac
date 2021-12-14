use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{message_key::RemoteMessageKey, ratchet::RatchetPublicKey, MessageKey};

const MESSAGE_KEY_SEED: &[u8; 1] = b"\x01";
const ADVANCEMENT_SEED: &[u8; 1] = b"\x02";

fn expand_chain_key(key: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("Can't create HmacSha256 from the key");
    mac.update(MESSAGE_KEY_SEED);

    let output = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(output.as_slice());

    key
}

pub(super) struct ChainKey {
    key: [u8; 32],
    index: u64,
}

#[derive(Debug)]
pub(super) struct RemoteChainKey {
    key: [u8; 32],
    index: u64,
}

impl RemoteChainKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { key: bytes, index: 0 }
    }

    pub fn fill(&mut self, key: &[u8]) {
        self.key.copy_from_slice(key);
    }

    fn advance(&mut self) {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(ADVANCEMENT_SEED);

        let output = mac.finalize().into_bytes();
        self.key.copy_from_slice(output.as_slice());
        self.index += 1;
    }

    pub fn create_message_key(&mut self) -> RemoteMessageKey {
        let key = expand_chain_key(&self.key);
        let message_key = RemoteMessageKey::new(key, self.index);

        self.advance();

        message_key
    }
}

impl ChainKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { key: bytes, index: 0 }
    }

    pub fn fill(&mut self, key: &[u8]) {
        self.key.copy_from_slice(key);
    }

    fn advance(&mut self) {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(ADVANCEMENT_SEED);

        let output = mac.finalize().into_bytes();
        self.key.copy_from_slice(output.as_slice());
        self.index += 1;
    }

    pub fn create_message_key(&mut self, ratchet_key: RatchetPublicKey) -> MessageKey {
        let key = expand_chain_key(&self.key);
        let message_key = MessageKey::new(key, ratchet_key, self.index);

        self.advance();

        message_key
    }
}
