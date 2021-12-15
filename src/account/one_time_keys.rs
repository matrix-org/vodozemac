use std::collections::HashMap;

use rand::thread_rng;
use x25519_dalek::{PublicKey as Curve25591PublicKey, StaticSecret as Curve25591SecretKey};

use super::types::KeyId;

pub(super) struct OneTimeKeys {
    key_id: u64,
    pub public_keys: HashMap<KeyId, Curve25591PublicKey>,
    pub private_keys: HashMap<KeyId, Curve25591SecretKey>,
    pub reverse_public_keys: HashMap<Curve25591PublicKey, KeyId>,
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

    pub fn get_secret_key(&self, public_key: &Curve25591PublicKey) -> Option<&Curve25591SecretKey> {
        self.reverse_public_keys.get(public_key).and_then(|key_id| self.private_keys.get(key_id))
    }

    pub fn remove_secret_key(
        &mut self,
        public_key: &Curve25591PublicKey,
    ) -> Option<Curve25591SecretKey> {
        self.reverse_public_keys
            .remove(public_key)
            .and_then(|key_id| self.private_keys.remove(&key_id))
    }

    pub fn generate(&mut self, count: usize) {
        let mut rng = thread_rng();

        for _ in 0..count {
            let key_id = KeyId(self.key_id);
            let secret_key = Curve25591SecretKey::new(&mut rng);
            let public_key = Curve25591PublicKey::from(&secret_key);

            self.private_keys.insert(key_id, secret_key);
            self.public_keys.insert(key_id, public_key);
            self.reverse_public_keys.insert(public_key, key_id);

            self.key_id += 1;
        }
    }
}
