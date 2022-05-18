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
use sha2::{digest::CtOutput, Sha256};
use zeroize::Zeroize;

use super::{
    message_key::{MessageKey, RemoteMessageKey},
    ratchet::RatchetPublicKey,
};

const MESSAGE_KEY_SEED: &[u8; 1] = b"\x01";
const ADVANCEMENT_SEED: &[u8; 1] = b"\x02";

fn expand_chain_key(key: &[u8; 32]) -> Box<[u8; 32]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("Can't create HmacSha256 from the key");
    mac.update(MESSAGE_KEY_SEED);

    let mut output = mac.finalize().into_bytes();

    let mut key = Box::new([0u8; 32]);
    key.copy_from_slice(output.as_slice());

    output.zeroize();

    key
}

fn advance(key: &[u8; 32]) -> CtOutput<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("Coulnd't create a valid Hmac object to advance the ratchet");
    mac.update(ADVANCEMENT_SEED);

    mac.finalize()
}

#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub(super) struct ChainKey {
    key: Box<[u8; 32]>,
    index: u64,
}

#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub(super) struct RemoteChainKey {
    key: Box<[u8; 32]>,
    index: u64,
}

impl RemoteChainKey {
    pub fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes, index: 0 }
    }

    pub fn chain_index(&self) -> u64 {
        self.index
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_bytes_and_index(bytes: Box<[u8; 32]>, index: u32) -> Self {
        Self { key: bytes, index: index.into() }
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
    pub fn new(bytes: Box<[u8; 32]>) -> Self {
        Self { key: bytes, index: 0 }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_bytes_and_index(bytes: Box<[u8; 32]>, index: u32) -> Self {
        Self { key: bytes, index: index.into() }
    }

    pub fn advance(&mut self) {
        let output = advance(&self.key).into_bytes();
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
