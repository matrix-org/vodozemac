// Copyright 2021 Damir Jelić
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

//! A 3DH implementation following the Olm [spec].
//!
//! The setup takes four Curve25519 inputs: Identity keys for Alice and Bob,
//! (Ia, Ib), and one-time keys for Alice and Bob (Ea, Eb).
//!
//! A shared secret S is generated via Triple Diffie-Hellman using the above
//! inputs. The initial 256-bit root key R0 and a 256-bit chain key C0,0 are
//! derived from the shared secret using an HMAC-based Key Derivation Function
//! with SHA-256 as the hash function (HKDF-SHA-256), the default salt and
//! "OLM_ROOT" as the info.
//!
//! ```text
//!     S = ECDH(Ia, Eb) || ECDH(Ea, Ib) || ECDH (Ea, Eb)
//!
//!     R0, C0,0 = HKDF(0, S, "OLM_ROOT", 64)
//! ```
//!
//! [spec]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#initial-setup

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{ReusableSecret, SharedSecret};
use zeroize::Zeroize;

use crate::{types::Curve25519SecretKey as StaticSecret, Curve25519PublicKey as PublicKey};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Shared3DHSecret(Box<[u8; 96]>);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RemoteShared3DHSecret(Box<[u8; 96]>);

fn expand(shared_secret: &[u8; 96]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), shared_secret);
    let mut root_key = Box::new([0u8; 32]);
    let mut chain_key = Box::new([0u8; 32]);

    let mut expanded_keys = [0u8; 64];

    hkdf.expand(b"OLM_ROOT", &mut expanded_keys)
        .expect("Can't expand the shared 3DH secret into the Olm root");

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    expanded_keys.zeroize();

    (root_key, chain_key)
}

fn merge_secrets(
    first_secret: SharedSecret,
    second_secret: SharedSecret,
    third_secret: SharedSecret,
) -> Box<[u8; 96]> {
    let mut secret = Box::new([0u8; 96]);

    secret[0..32].copy_from_slice(first_secret.as_bytes());
    secret[32..64].copy_from_slice(second_secret.as_bytes());
    secret[64..96].copy_from_slice(third_secret.as_bytes());

    secret
}

impl RemoteShared3DHSecret {
    pub(crate) fn new(
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

    pub fn expand(self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand(&self.0)
    }
}

impl Shared3DHSecret {
    pub(crate) fn new(
        identity_key: &StaticSecret,
        one_time_key: &ReusableSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = identity_key.diffie_hellman(remote_one_time_key);
        let second_secret = one_time_key.diffie_hellman(&remote_identity_key.inner);
        let third_secret = one_time_key.diffie_hellman(&remote_one_time_key.inner);

        Self(merge_secrets(first_secret, second_secret, third_secret))
    }

    pub fn expand(self) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        expand(&self.0)
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use x25519_dalek::ReusableSecret;

    use super::{RemoteShared3DHSecret, Shared3DHSecret};
    use crate::{types::Curve25519SecretKey as StaticSecret, Curve25519PublicKey as PublicKey};

    #[test]
    fn triple_diffie_hellman() {
        let mut rng = thread_rng();

        let alice_identity = StaticSecret::new();
        let alice_one_time = ReusableSecret::new(&mut rng);

        let bob_identity = StaticSecret::new();
        let bob_one_time = StaticSecret::new();

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
