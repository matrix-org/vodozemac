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

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret as Curve25519SecretKey;
use zeroize::Zeroize;

use crate::{types::KeyId, Curve25519PublicKey};

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct FallbackKey {
    pub key_id: KeyId,
    pub key: Curve25519SecretKey,
    pub published: bool,
}

impl FallbackKey {
    fn new(key_id: KeyId) -> Self {
        let mut rng = thread_rng();
        let key = Curve25519SecretKey::new(&mut rng);

        Self { key_id, key, published: false }
    }

    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(&self.key)
    }

    pub fn secret_key(&self) -> &Curve25519SecretKey {
        &self.key
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn mark_as_published(&mut self) {
        self.published = true;
    }

    pub fn published(&self) -> bool {
        self.published
    }
}

impl Zeroize for FallbackKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct FallbackKeys {
    pub key_id: u64,
    pub fallback_key: Option<FallbackKey>,
    pub previous_fallback_key: Option<FallbackKey>,
}

impl FallbackKeys {
    pub fn new() -> Self {
        Self { key_id: 0, fallback_key: None, previous_fallback_key: None }
    }

    pub fn mark_as_published(&mut self) {
        if let Some(f) = self.fallback_key.as_mut() {
            f.mark_as_published()
        }
    }

    pub fn generate_fallback_key(&mut self) {
        let key_id = KeyId(self.key_id);
        self.key_id += 1;

        self.previous_fallback_key = self.fallback_key.take();
        self.fallback_key = Some(FallbackKey::new(key_id))
    }

    pub fn get_secret_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.fallback_key
            .as_ref()
            .filter(|f| f.public_key() == *public_key)
            .or_else(|| {
                self.previous_fallback_key.as_ref().filter(|f| f.public_key() == *public_key)
            })
            .map(|f| f.secret_key())
    }

    pub fn forget_previous_fallback_key(&mut self) -> Option<FallbackKey> {
        self.previous_fallback_key.take()
    }

    pub fn unpublished_fallback_key(&self) -> Option<&FallbackKey> {
        self.fallback_key.as_ref().filter(|f| !f.published())
    }
}

#[cfg(test)]
mod test {
    use super::FallbackKeys;

    #[test]
    fn fallback_key_fetching() {
        let err = "Missing fallback key";
        let mut fallback_keys = FallbackKeys::new();

        fallback_keys.generate_fallback_key();

        let public_key = fallback_keys.fallback_key.as_ref().expect(err).public_key();
        let secret_bytes = fallback_keys.fallback_key.as_ref().expect(err).key.to_bytes();

        let fetched_key = fallback_keys.get_secret_key(&public_key).expect(err);

        assert_eq!(secret_bytes, fetched_key.to_bytes());

        fallback_keys.generate_fallback_key();

        let fetched_key = fallback_keys.get_secret_key(&public_key).expect(err);
        assert_eq!(secret_bytes, fetched_key.to_bytes());

        let public_key = fallback_keys.fallback_key.as_ref().expect(err).public_key();
        let secret_bytes = fallback_keys.fallback_key.as_ref().expect(err).key.to_bytes();

        let fetched_key = fallback_keys.get_secret_key(&public_key).expect(err);

        assert_eq!(secret_bytes, fetched_key.to_bytes());
    }
}
