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

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, digest::CtOutput};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    message_key::{MessageKey, RemoteMessageKey},
    ratchet::RatchetPublicKey,
};

const MESSAGE_KEY_SEED: &[u8; 1] = b"\x01";
const ADVANCEMENT_SEED: &[u8; 1] = b"\x02";

fn expand_chain_key(key: &[u8; 32]) -> Box<[u8; 32]> {
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("We should be able to create a HMAC object from a 32-byte key");
    mac.update(MESSAGE_KEY_SEED);

    let mut output = mac.finalize().into_bytes();

    let mut key = Box::new([0u8; 32]);
    key.copy_from_slice(output.as_slice());

    output.zeroize();

    key
}

fn advance(key: &[u8; 32]) -> CtOutput<Hmac<Sha256>> {
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect(
        "We should be able to create a HMAC object from a 32-byte key to advance the ratchet",
    );
    mac.update(ADVANCEMENT_SEED);

    mac.finalize()
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(super) struct ChainKey {
    key: Box<[u8; 32]>,
    index: u64,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(super) struct RemoteChainKey {
    key: Box<[u8; 32]>,
    index: u64,
}

impl RemoteChainKey {
    pub const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes, index: 0 }
    }

    pub const fn chain_index(&self) -> u64 {
        self.index
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_bytes_and_index(bytes: Box<[u8; 32]>, index: u32) -> Self {
        Self { key: bytes, index: index.into() }
    }

    #[cfg(feature = "libolm-compat")]
    #[allow(clippy::borrowed_box)]
    pub fn as_bytes(&self) -> &Box<[u8; 32]> {
        &self.key
    }

    pub fn advance(&mut self) {
        let output = advance(&self.key).into_bytes();
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
    pub const fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes, index: 0 }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_bytes_and_index(bytes: Box<[u8; 32]>, index: u32) -> Self {
        Self { key: bytes, index: index.into() }
    }

    /// Get the chain key as a boxed slice of bytes.
    #[cfg(feature = "libolm-compat")]
    #[allow(clippy::borrowed_box)]
    pub fn as_bytes(&self) -> &Box<[u8; 32]> {
        &self.key
    }

    pub fn advance(&mut self) {
        let output = advance(&self.key).into_bytes();
        self.key.copy_from_slice(output.as_slice());
        self.index += 1;
    }

    /// Get the chain index of this [`ChainKey`]
    ///
    /// The chain index indicates how many times the key has been advanced using
    /// [`ChainKey::advance`].
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub fn create_message_key(&mut self, ratchet_key: RatchetPublicKey) -> MessageKey {
        let key = expand_chain_key(&self.key);
        let message_key = MessageKey::new(key, ratchet_key, self.index);

        self.advance();

        message_key
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "libolm-compat")]
    use rand::{Fill, thread_rng};

    use super::ChainKey;
    use crate::olm::session::chain_key::RemoteChainKey;

    #[test]
    fn advancing_chain_key_increments_index() {
        let mut key = ChainKey::new(Box::new(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(key.index(), 0);
        key.advance();
        assert_eq!(key.index(), 1);
    }

    #[test]
    fn advancing_remote_chain_key_increments_index() {
        let mut key = RemoteChainKey::new(Box::new(*b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(key.chain_index(), 0);
        key.advance();
        assert_eq!(key.chain_index(), 1);
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn chain_key_as_bytes() {
        let mut rng = thread_rng();
        let mut bytes = Box::new([0u8; 32]);
        bytes.try_fill(&mut rng).unwrap();

        let key = ChainKey::new(bytes.clone());

        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn remote_chain_key_as_bytes() {
        let mut rng = thread_rng();
        let mut bytes = Box::new([0u8; 32]);
        bytes.try_fill(&mut rng).unwrap();

        let key = RemoteChainKey::new(bytes.clone());

        assert_eq!(key.as_bytes(), &bytes);
    }
}
