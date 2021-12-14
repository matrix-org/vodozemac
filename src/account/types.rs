use dashmap::DashMap;
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct KeyId(String);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        value.0
    }
}

pub(super) struct OneTimeKeys {
    key_id: u64,
    pub public_keys: DashMap<KeyId, Curve25591PublicKey>,
    pub private_keys: DashMap<KeyId, Curve25591SecretKey>,
    pub reverse_public_keys: DashMap<Curve25591PublicKey, KeyId>,
}

impl OneTimeKeys {
    pub fn new() -> Self {
        Self {
            key_id: 0,
            public_keys: DashMap::new(),
            private_keys: DashMap::new(),
            reverse_public_keys: DashMap::new(),
        }
    }

    pub fn mark_as_published(&self) {
        self.public_keys.clear();
    }

    pub fn get_secret_key(&self, public_key: Curve25591PublicKey) -> Option<Curve25591SecretKey> {
        self.reverse_public_keys
            .remove(&public_key)
            .and_then(|(_, key_id)| self.private_keys.remove(&key_id).map(|(_, v)| v))
    }

    pub fn generate(&mut self, count: usize) {
        let mut rng = thread_rng();

        for _ in 0..count {
            let key_id = KeyId(encode(self.key_id.to_le_bytes()));
            let secret_key = Curve25591SecretKey::new(&mut rng);
            let public_key = Curve25591PublicKey::from(&secret_key);

            self.private_keys.insert(key_id.clone(), secret_key);
            self.public_keys.insert(key_id.clone(), public_key);
            self.reverse_public_keys.insert(public_key, key_id);

            self.key_id += 1;
        }
    }
}
