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

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::PUBLIC_MAX_ONE_TIME_KEYS;
use crate::{
    types::{Curve25519SecretKey, KeyId},
    Curve25519PublicKey,
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(from = "OneTimeKeysPickle")]
#[serde(into = "OneTimeKeysPickle")]
pub(super) struct OneTimeKeys {
    pub next_key_id: u64,
    pub unpublished_public_keys: BTreeMap<KeyId, Curve25519PublicKey>,
    pub private_keys: BTreeMap<KeyId, Curve25519SecretKey>,
    pub key_ids_by_key: HashMap<Curve25519PublicKey, KeyId>,
}

/// The result type for the one-time key generation operation.
pub struct OneTimeKeyGenerationResult {
    /// The public part of the one-time keys that were newly generated.
    pub created: Vec<Curve25519PublicKey>,
    /// The public part of the one-time keys that had to be removed to make
    /// space for the new ones.
    pub removed: Vec<Curve25519PublicKey>,
}

impl OneTimeKeys {
    const MAX_ONE_TIME_KEYS: usize = 100 * PUBLIC_MAX_ONE_TIME_KEYS;

    pub fn new() -> Self {
        Self {
            next_key_id: 0,
            unpublished_public_keys: Default::default(),
            private_keys: Default::default(),
            key_ids_by_key: Default::default(),
        }
    }

    pub fn mark_as_published(&mut self) {
        self.unpublished_public_keys.clear();
    }

    pub fn get_secret_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.key_ids_by_key.get(public_key).and_then(|key_id| self.private_keys.get(key_id))
    }

    pub fn remove_secret_key(
        &mut self,
        public_key: &Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.key_ids_by_key.remove(public_key).and_then(|key_id| {
            self.unpublished_public_keys.remove(&key_id);
            self.private_keys.remove(&key_id)
        })
    }

    pub(super) fn insert_secret_key(
        &mut self,
        key_id: KeyId,
        key: Curve25519SecretKey,
        published: bool,
    ) -> (Curve25519PublicKey, Option<Curve25519PublicKey>) {
        // If we hit the max number of one-time keys we'd like to keep, first remove one
        // before we create a new one.
        let removed = if self.private_keys.len() >= Self::MAX_ONE_TIME_KEYS {
            if let Some(key_id) = self.private_keys.keys().next().copied() {
                let public_key = if let Some(private_key) = self.private_keys.remove(&key_id) {
                    let public_key = Curve25519PublicKey::from(&private_key);
                    self.key_ids_by_key.remove(&public_key);

                    Some(public_key)
                } else {
                    None
                };

                self.unpublished_public_keys.remove(&key_id);

                public_key
            } else {
                None
            }
        } else {
            None
        };

        let public_key = Curve25519PublicKey::from(&key);

        self.private_keys.insert(key_id, key);
        self.key_ids_by_key.insert(public_key, key_id);

        if !published {
            self.unpublished_public_keys.insert(key_id, public_key);
        }

        (public_key, removed)
    }

    fn generate_one_time_key(&mut self) -> (Curve25519PublicKey, Option<Curve25519PublicKey>) {
        let key_id = KeyId(self.next_key_id);
        let key = Curve25519SecretKey::new();
        self.insert_secret_key(key_id, key, false)
    }

    pub(crate) const fn secret_keys(&self) -> &BTreeMap<KeyId, Curve25519SecretKey> {
        &self.private_keys
    }

    pub(crate) fn is_secret_key_published(&self, key_id: &KeyId) -> bool {
        !self.unpublished_public_keys.contains_key(key_id)
    }

    pub fn generate(&mut self, count: usize) -> OneTimeKeyGenerationResult {
        let mut removed_keys = Vec::new();
        let mut created_keys = Vec::new();

        for _ in 0..count {
            let (created, removed) = self.generate_one_time_key();

            created_keys.push(created);
            if let Some(removed) = removed {
                removed_keys.push(removed);
            }

            self.next_key_id = self.next_key_id.wrapping_add(1);
        }

        OneTimeKeyGenerationResult { created: created_keys, removed: removed_keys }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct OneTimeKeysPickle {
    #[serde(alias = "key_id")]
    next_key_id: u64,
    public_keys: BTreeMap<KeyId, Curve25519PublicKey>,
    private_keys: BTreeMap<KeyId, Curve25519SecretKey>,
}

impl From<OneTimeKeysPickle> for OneTimeKeys {
    fn from(pickle: OneTimeKeysPickle) -> Self {
        let mut key_ids_by_key = HashMap::new();

        for (k, v) in pickle.private_keys.iter() {
            key_ids_by_key.insert(v.into(), *k);
        }

        Self {
            next_key_id: pickle.next_key_id,
            unpublished_public_keys: pickle.public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: pickle.private_keys,
            key_ids_by_key,
        }
    }
}

impl From<OneTimeKeys> for OneTimeKeysPickle {
    fn from(keys: OneTimeKeys) -> Self {
        OneTimeKeysPickle {
            next_key_id: keys.next_key_id,
            public_keys: keys.unpublished_public_keys.iter().map(|(&k, &v)| (k, v)).collect(),
            private_keys: keys.private_keys,
        }
    }
}

#[cfg(test)]
mod test {
    use super::OneTimeKeys;
    use crate::types::KeyId;

    #[test]
    fn store_limit() {
        let mut store = OneTimeKeys::new();

        assert!(store.private_keys.is_empty());

        store.generate(OneTimeKeys::MAX_ONE_TIME_KEYS);
        assert_eq!(store.unpublished_public_keys.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);
        assert_eq!(store.private_keys.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);
        assert_eq!(store.key_ids_by_key.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);

        store
            .private_keys
            .keys()
            .for_each(|key_id| assert!(!store.is_secret_key_published(key_id)));

        store.mark_as_published();
        assert!(store.unpublished_public_keys.is_empty());
        assert_eq!(store.private_keys.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);
        assert_eq!(store.key_ids_by_key.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);

        store.private_keys.keys().for_each(|key_id| assert!(store.is_secret_key_published(key_id)));

        let oldest_key_id =
            store.private_keys.keys().next().copied().expect("Couldn't get the first key ID");
        assert_eq!(oldest_key_id, KeyId(0));

        store.generate(10);
        assert_eq!(store.unpublished_public_keys.len(), 10);
        assert_eq!(store.private_keys.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);
        assert_eq!(store.key_ids_by_key.len(), OneTimeKeys::MAX_ONE_TIME_KEYS);

        store
            .private_keys
            .keys()
            .take(OneTimeKeys::MAX_ONE_TIME_KEYS - 10)
            .for_each(|key_id| assert!(store.is_secret_key_published(key_id)));
        store
            .private_keys
            .keys()
            .skip(OneTimeKeys::MAX_ONE_TIME_KEYS - 10)
            .for_each(|key_id| assert!(!store.is_secret_key_published(key_id)));

        let oldest_key_id =
            store.private_keys.keys().next().copied().expect("Couldn't get the first key ID");

        assert_eq!(oldest_key_id, KeyId(10));
    }
}
