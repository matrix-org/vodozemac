use rand::thread_rng;
use x25519_dalek::{PublicKey as Curve25591PublicKey, StaticSecret as Curve25591SecretKey};

use super::types::KeyId;

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
