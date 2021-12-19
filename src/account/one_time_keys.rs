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

use std::collections::HashMap;

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret as Curve25519SecretKey;
use zeroize::Zeroize;

use crate::{types::KeyId, Curve25519PublicKey};

#[derive(Serialize, Deserialize, Clone)]
#[serde(from = "OneTimeKeysPickle")]
#[serde(into = "OneTimeKeysPickle")]
pub(super) struct OneTimeKeys {
    key_id: u64,
    pub public_keys: HashMap<KeyId, Curve25519PublicKey>,
    pub private_keys: HashMap<KeyId, Curve25519SecretKey>,
    pub reverse_public_keys: HashMap<Curve25519PublicKey, KeyId>,
}

impl Zeroize for OneTimeKeysPickle {
    fn zeroize(&mut self) {
        for k in self.private_keys.values_mut() {
            k.zeroize()
        }
    }
}

impl OneTimeKeys {
    pub fn new() -> Self {
        Self {
            key_id: 0,
            public_keys: Default::default(),
            private_keys: Default::default(),
            reverse_public_keys: Default::default(),
        }
    }

    pub fn mark_as_published(&mut self) {
        self.public_keys.clear();
    }

    pub fn get_secret_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.reverse_public_keys.get(public_key).and_then(|key_id| self.private_keys.get(key_id))
    }

    pub fn remove_secret_key(
        &mut self,
        public_key: &Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.reverse_public_keys
            .remove(public_key)
            .and_then(|key_id| self.private_keys.remove(&key_id))
    }

    pub fn generate(&mut self, count: usize) {
        let mut rng = thread_rng();

        for _ in 0..count {
            let key_id = KeyId(self.key_id);
            let secret_key = Curve25519SecretKey::new(&mut rng);
            let public_key = Curve25519PublicKey::from(&secret_key);

            self.private_keys.insert(key_id, secret_key);
            self.public_keys.insert(key_id, public_key);
            self.reverse_public_keys.insert(public_key, key_id);

            self.key_id += 1;
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct OneTimeKeysPickle {
    key_id: u64,
    public_keys: HashMap<KeyId, Curve25519PublicKey>,
    private_keys: HashMap<KeyId, Curve25519SecretKey>,
}

impl From<OneTimeKeysPickle> for OneTimeKeys {
    fn from(pickle: OneTimeKeysPickle) -> Self {
        let mut reverse_public_keys = HashMap::new();

        for (k, v) in pickle.public_keys.clone().into_iter() {
            reverse_public_keys.insert(v, k);
        }

        Self {
            key_id: pickle.key_id,
            public_keys: pickle.public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: pickle.private_keys,
            reverse_public_keys,
        }
    }
}

impl From<OneTimeKeys> for OneTimeKeysPickle {
    fn from(keys: OneTimeKeys) -> Self {
        OneTimeKeysPickle {
            key_id: keys.key_id,
            public_keys: keys.public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: keys.private_keys,
        }
    }
}
