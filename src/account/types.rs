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
pub struct KeyId(pub(super) u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        encode(value.0.to_le_bytes())
    }
}
