// Copyright 2024 Damir Jelić
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

use hkdf::Hkdf;
use sha2::Sha512;
use x25519_dalek::{ReusableSecret, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    olm::shared_secret::expand,
    types::{
        kyber::{KyberCipherText, KyberSecretKey, KyberSharedSecret},
        KyberPublicKey,
    },
    Curve25519PublicKey, Curve25519SecretKey,
};

const PROTOCOL_NAME: &[u8] = b"OLM_CURVE25519_SHA-512_CRYSTALS-KYBER-1024";

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SharedPqXDHSecret {
    pub secret_key: Box<[u8; 32]>,
    #[zeroize(skip)]
    pub kyber_ciphertext: KyberCipherText,
}

impl SharedPqXDHSecret {
    pub(crate) fn new(
        identity_key: &Curve25519SecretKey,
        base_key: &ReusableSecret,
        remote_identity_key: &Curve25519PublicKey,
        remote_signed_prekey: &Curve25519PublicKey,
        remote_one_time_key: Option<&Curve25519PublicKey>,
        kyber_key: &KyberPublicKey,
    ) -> Self {
        let first_secret = identity_key.diffie_hellman(remote_signed_prekey);
        let second_secret = base_key.diffie_hellman(&remote_identity_key.inner);
        let third_secret = base_key.diffie_hellman(&remote_signed_prekey.inner);
        let fourth_secret = remote_one_time_key.map(|otk| base_key.diffie_hellman(&otk.inner));

        let encapsulation_result = kyber_key.encapsulate();
        let fifth_secret = encapsulation_result.shared_secret;

        let secret_key =
            merge_secrets(first_secret, second_secret, third_secret, fourth_secret, fifth_secret);

        Self { secret_key, kyber_ciphertext: encapsulation_result.ciphertext }
    }

    pub(crate) fn expand(&self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand(self.secret_key.as_slice())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct RemoteSharedPqXDHSecret {
    pub secret_key: Box<[u8; 32]>,
}

impl RemoteSharedPqXDHSecret {
    pub(crate) fn new(
        identity_key: &Curve25519SecretKey,
        signed_prekey: &Curve25519SecretKey,
        one_time_key: Option<&Curve25519SecretKey>,
        remote_identity_key: &Curve25519PublicKey,
        remote_base_key: &Curve25519PublicKey,
        kyber_key: &KyberSecretKey,
        kyber_ciphertext: &KyberCipherText,
    ) -> Result<Self, ()> {
        let first_secret = signed_prekey.diffie_hellman(remote_identity_key);
        let second_secret = identity_key.diffie_hellman(remote_base_key);
        let third_secret = signed_prekey.diffie_hellman(remote_base_key);
        let fourth_secret = one_time_key.map(|otk| otk.diffie_hellman(remote_base_key));

        let fifth_secret = kyber_key.decapsulate(kyber_ciphertext)?;

        let secret_key =
            merge_secrets(first_secret, second_secret, third_secret, fourth_secret, fifth_secret);

        Ok(Self { secret_key })
    }

    pub(crate) fn expand(&self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand(self.secret_key.as_slice())
    }
}

fn merge_secrets(
    first_secret: SharedSecret,
    second_secret: SharedSecret,
    third_secret: SharedSecret,
    fourth_secret: Option<SharedSecret>,
    fifth_secret: KyberSharedSecret,
) -> Box<[u8; 32]> {
    let mut merged_secret = Vec::with_capacity(5 * 32);

    merged_secret.extend_from_slice(&[0xFFu8; 32]);
    merged_secret.extend_from_slice(first_secret.as_bytes());
    merged_secret.extend_from_slice(second_secret.as_bytes());
    merged_secret.extend_from_slice(third_secret.as_bytes());

    if let Some(s) = fourth_secret {
        merged_secret.extend_from_slice(s.as_bytes());
    }

    merged_secret.extend_from_slice(fifth_secret.as_bytes());

    let salt = [0u8; 32];

    let hkdf: Hkdf<Sha512> = Hkdf::new(Some(&salt), &merged_secret);
    let mut secret_key = Box::new([0u8; 32]);

    hkdf.expand(PROTOCOL_NAME, secret_key.as_mut_slice())
        .expect("We should be able to expand the merged PQXDH secrets into a 32 byte secret key");

    secret_key
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn pqxdh() {
        let mut rng = thread_rng();

        let alice_identity = Curve25519SecretKey::new();
        let alice_base = ReusableSecret::random_from_rng(&mut rng);

        let alice_identity_public = Curve25519PublicKey::from(&alice_identity);
        let alice_base_public = Curve25519PublicKey::from(&alice_base);

        let bob_identity = Curve25519SecretKey::new();
        let bob_one_time = Curve25519SecretKey::new();
        let bob_signed_pre_key = Curve25519SecretKey::new();
        let bob_kyber = KyberSecretKey::new();

        let bob_identity_public = Curve25519PublicKey::from(&bob_identity);
        let bob_one_time_public = Curve25519PublicKey::from(&bob_one_time);
        let bob_signed_pre_key_public = Curve25519PublicKey::from(&bob_signed_pre_key);

        let shared_secret = SharedPqXDHSecret::new(
            &alice_identity,
            &alice_base,
            &bob_identity_public,
            &bob_signed_pre_key_public,
            Some(&bob_one_time_public),
            &bob_kyber.public_key(),
        );

        let remote_shared_secret = RemoteSharedPqXDHSecret::new(
            &bob_identity,
            &bob_signed_pre_key,
            Some(&bob_one_time),
            &alice_identity_public,
            &alice_base_public,
            &bob_kyber,
            &shared_secret.kyber_ciphertext,
        )
        .expect("We should be able to create a RemoteSharedPqXDHSecret from our input keys");

        assert_eq!(
            shared_secret.secret_key, remote_shared_secret.secret_key,
            "We should have derived the same secret key"
        );

        assert_ne!(&*shared_secret.secret_key, &[0u8; 32])
    }

    #[test]
    fn pqxdh_without_one_time_key() {
        let mut rng = thread_rng();

        let alice_identity = Curve25519SecretKey::new();
        let alice_base = ReusableSecret::random_from_rng(&mut rng);

        let alice_identity_public = Curve25519PublicKey::from(&alice_identity);
        let alice_base_public = Curve25519PublicKey::from(&alice_base);

        let bob_identity = Curve25519SecretKey::new();
        let bob_signed_pre_key = Curve25519SecretKey::new();
        let bob_kyber = KyberSecretKey::new();

        let bob_identity_public = Curve25519PublicKey::from(&bob_identity);
        let bob_signed_pre_key_public = Curve25519PublicKey::from(&bob_signed_pre_key);

        let shared_secret = SharedPqXDHSecret::new(
            &alice_identity,
            &alice_base,
            &bob_identity_public,
            &bob_signed_pre_key_public,
            None,
            &bob_kyber.public_key(),
        );

        let remote_shared_secret = RemoteSharedPqXDHSecret::new(
            &bob_identity,
            &bob_signed_pre_key,
            None,
            &alice_identity_public,
            &alice_base_public,
            &bob_kyber,
            &shared_secret.kyber_ciphertext,
        )
        .expect("We should be able to create a RemoteSharedPqXDHSecret from our input keys");

        assert_eq!(
            shared_secret.secret_key, remote_shared_secret.secret_key,
            "We should have derived the same secret key"
        );
    }
}
