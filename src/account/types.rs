use std::collections::HashMap;

use ed25519_dalek::{Keypair, PublicKey as Ed25519PublicKey, Signer};
use rand::thread_rng;
use x25519_dalek::{PublicKey as Curve25591PublicKey, StaticSecret as Curve25591SecretKey};

use crate::utilities::encode;

pub(super) struct Ed25519Keypair {
    inner: Keypair,
    encoded_public_key: String,
}

impl Ed25519Keypair {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let encoded_public_key = encode(keypair.public.as_bytes());

        Self { inner: keypair, encoded_public_key }
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.inner.public
    }

    pub fn sign(&self, message: &str) -> String {
        let signature = self.inner.sign(message.as_bytes());
        encode(signature.to_bytes())
    }
}

pub(super) struct Curve25519Keypair {
    secret_key: Curve25591SecretKey,
    public_key: Curve25591PublicKey,
    encoded_public_key: String,
}

impl Curve25519Keypair {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = Curve25591SecretKey::new(&mut rng);
        let public_key = Curve25591PublicKey::from(&secret_key);
        let encoded_public_key = encode(public_key.as_bytes());

        Self { secret_key, public_key, encoded_public_key }
    }

    pub fn secret_key(&self) -> &Curve25591SecretKey {
        &self.secret_key
    }

    pub fn public_key(&self) -> &Curve25591PublicKey {
        &self.public_key
    }

    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct KeyId(u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        encode(value.0.to_le_bytes())
    }
}

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
        self.reverse_public_keys.get(public_key).and_then(|key_id| self.private_keys.get(&key_id))
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

            self.private_keys.insert(key_id.clone(), secret_key);
            self.public_keys.insert(key_id.clone(), public_key);
            self.reverse_public_keys.insert(public_key, key_id);

            self.key_id += 1;
        }
    }
}

pub(super) struct FallbackKey {
    key_id: KeyId,
    key: Curve25591SecretKey,
    published: bool,
}

impl FallbackKey {
    fn new(key_id: KeyId) -> Self {
        let mut rng = thread_rng();
        let key = Curve25591SecretKey::new(&mut rng);

        Self { key_id, key, published: false }
    }

    pub fn public_key(&self) -> Curve25591PublicKey {
        Curve25591PublicKey::from(&self.key)
    }

    pub fn secret_key(&self) -> &Curve25591SecretKey {
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

pub(super) struct FallbackKeys {
    key_id: u64,
    pub fallback_key: Option<FallbackKey>,
    pub previous_fallback_key: Option<FallbackKey>,
}

impl FallbackKeys {
    pub fn new() -> Self {
        Self { key_id: 0, fallback_key: None, previous_fallback_key: None }
    }

    pub fn mark_as_published(&mut self) {
        self.fallback_key.as_mut().map(|f| f.mark_as_published());
    }

    pub fn generate_fallback_key(&mut self) {
        let key_id = KeyId(self.key_id);
        self.key_id += 1;

        self.previous_fallback_key = self.fallback_key.take();
        self.fallback_key = Some(FallbackKey::new(key_id))
    }

    pub fn get_secret_key(&self, public_key: &Curve25591PublicKey) -> Option<&Curve25591SecretKey> {
        self.fallback_key
            .as_ref()
            .filter(|f| f.public_key() == *public_key)
            .or_else(|| {
                self.previous_fallback_key.as_ref().filter(|f| f.public_key() == *public_key)
            })
            .map(|f| f.secret_key())
    }

    pub fn remove_previous_fallback_key(&mut self) -> Option<FallbackKey> {
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
        let mut fallback_keys = FallbackKeys::new();

        fallback_keys.generate_fallback_key();

        let public_key = fallback_keys.fallback_key.as_ref().unwrap().public_key();
        let secret_bytes = fallback_keys.fallback_key.as_ref().unwrap().key.to_bytes();

        let fetched_key = fallback_keys.get_secret_key(&public_key).unwrap();

        assert_eq!(secret_bytes, fetched_key.to_bytes());

        fallback_keys.generate_fallback_key();

        let fetched_key = fallback_keys.get_secret_key(&public_key).unwrap();
        assert_eq!(secret_bytes, fetched_key.to_bytes());

        let public_key = fallback_keys.fallback_key.as_ref().unwrap().public_key();
        let secret_bytes = fallback_keys.fallback_key.as_ref().unwrap().key.to_bytes();

        let fetched_key = fallback_keys.get_secret_key(&public_key).unwrap();

        assert_eq!(secret_bytes, fetched_key.to_bytes());
    }
}
