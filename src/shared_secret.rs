use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub struct Shared3DHSecret([u8; 96]);
pub struct RemoteShared3DHSecret([u8; 96]);

fn expand(shared_secret: [u8; 96]) -> ([u8; 32], [u8; 32]) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), &shared_secret);
    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];

    // TODO zeroize this.
    let mut expanded_keys = [0u8; 64];

    hkdf.expand(b"OLM_ROOT", &mut expanded_keys).unwrap();

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    (root_key, chain_key)
}

fn merge_secrets(
    first_secret: SharedSecret,
    second_secret: SharedSecret,
    third_secret: SharedSecret,
) -> [u8; 96] {
    let mut secret = [0u8; 96];

    secret[0..32].copy_from_slice(first_secret.as_bytes());
    secret[32..64].copy_from_slice(second_secret.as_bytes());
    secret[64..96].copy_from_slice(third_secret.as_bytes());

    secret
}

impl RemoteShared3DHSecret {
    pub fn new(
        identity_key: &StaticSecret,
        one_time_key: &StaticSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = one_time_key.diffie_hellman(remote_identity_key);
        let second_secret = identity_key.diffie_hellman(remote_one_time_key);
        let third_secret = one_time_key.diffie_hellman(remote_one_time_key);

        Self(merge_secrets(first_secret, second_secret, third_secret))
    }

    pub fn expand(self) -> ([u8; 32], [u8; 32]) {
        expand(self.0)
    }
}

impl Shared3DHSecret {
    pub fn new(
        identity_key: &StaticSecret,
        one_time_key: &StaticSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = identity_key.diffie_hellman(remote_one_time_key);
        let second_secret = one_time_key.diffie_hellman(remote_identity_key);
        let third_secret = one_time_key.diffie_hellman(remote_one_time_key);

        Self(merge_secrets(first_secret, second_secret, third_secret))
    }

    pub fn expand(self) -> ([u8; 32], [u8; 32]) {
        expand(self.0)
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{RemoteShared3DHSecret, Shared3DHSecret};

    #[test]
    fn tripple_diffie_hellman() {
        let mut rng = thread_rng();

        let alice_identity = StaticSecret::new(&mut rng);
        let alice_one_time = StaticSecret::new(&mut rng);

        let bob_identity = StaticSecret::new(&mut rng);
        let bob_one_time = StaticSecret::new(&mut rng);

        let alice_secret = Shared3DHSecret::new(
            &alice_identity,
            &alice_one_time,
            &PublicKey::from(&bob_identity),
            &PublicKey::from(&bob_one_time),
        );

        let bob_secret = RemoteShared3DHSecret::new(
            &bob_identity,
            &bob_one_time,
            &PublicKey::from(&alice_identity),
            &PublicKey::from(&alice_one_time),
        );

        assert_eq!(alice_secret.0, bob_secret.0);

        let alice_result = alice_secret.expand();
        let bob_result = bob_secret.expand();

        assert_eq!(alice_result, bob_result);
    }
}
