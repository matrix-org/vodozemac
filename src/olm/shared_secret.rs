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

//! A 3DH and X3DH implementation following the [Olm] and [Signal] specs.
//!
//! # Olm
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
//! # Signal
//!
//! Rather than repeating the contents here, we refer you to the [Signal] X3DH
//! spec.
//!
//! [Olm]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#initial-setup
//! [Signal]: https://signal.org/docs/specifications/x3dh/

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{ReusableSecret, SharedSecret};
use zeroize::Zeroize;

use super::{session_config::Version, SessionConfig};
use crate::{types::Curve25519SecretKey as StaticSecret, Curve25519PublicKey as PublicKey};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Shared3DHSecret(Vec<u8>);

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RemoteShared3DHSecret(Vec<u8>);

/// Expands secret input derived from the (X)3DH handshake into a root key and
/// chain key.
fn expand(secret_input: &[u8], info: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), secret_input);
    let mut root_key = Box::new([0u8; 32]);
    let mut chain_key = Box::new([0u8; 32]);

    let mut expanded_keys = [0u8; 64];

    hkdf.expand(info, &mut expanded_keys)
        .expect("Can't expand the shared 3DH secret into the Olm root");

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    expanded_keys.zeroize();

    (root_key, chain_key)
}

/// Expands secret input derived from the (X)3DH handshake into an Olm root key
/// and chain key.
fn expand_olm(secret_input: &[u8]) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
    expand(secret_input, b"OLM_ROOT")
}

fn merge_secrets_olm(
    first_secret: SharedSecret,
    second_secret: SharedSecret,
    third_secret: SharedSecret,
) -> Vec<u8> {
    let mut secret = Vec::with_capacity(4 * 32);

    secret.extend_from_slice(first_secret.as_bytes());
    secret.extend_from_slice(second_secret.as_bytes());
    secret.extend_from_slice(third_secret.as_bytes());

    secret
}

#[cfg(feature = "interolm")]
fn merge_secrets_x3dh(
    first_secret: SharedSecret,
    second_secret: SharedSecret,
    third_secret: SharedSecret,
    fourth_secret: Option<SharedSecret>,
) -> Vec<u8> {
    let mut secret = Vec::with_capacity(5 * 32);

    secret.extend_from_slice(&[0xFFu8; 32]);
    secret.extend_from_slice(first_secret.as_bytes());
    secret.extend_from_slice(second_secret.as_bytes());
    secret.extend_from_slice(third_secret.as_bytes());

    if let Some(s) = fourth_secret {
        secret.extend_from_slice(s.as_bytes());
    }

    secret
}

impl RemoteShared3DHSecret {
    pub(crate) fn new(
        config: &SessionConfig,
        identity_key: &StaticSecret,
        signed_prekey: &StaticSecret,
        one_time_key: Option<&StaticSecret>,
        remote_identity_key: &PublicKey,
        remote_base_key: &PublicKey,
    ) -> Self {
        let first_secret = signed_prekey.diffie_hellman(remote_identity_key);
        let second_secret = identity_key.diffie_hellman(remote_base_key);
        let third_secret = signed_prekey.diffie_hellman(remote_base_key);
        let fourth_secret = one_time_key.map(|otk| otk.diffie_hellman(remote_base_key));

        match config.version {
            Version::V1 | Version::V2 => {
                Self(merge_secrets_olm(first_secret, second_secret, third_secret))
            }
            #[cfg(feature = "interolm")]
            Version::Interolm(..) => {
                Self(merge_secrets_x3dh(first_secret, second_secret, third_secret, fourth_secret))
            }
        }
    }

    /// Expands secret input derived from the (X)3DH handshake into a root key
    /// and chain key.
    pub fn expand(self, config: &SessionConfig) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        match config.version {
            Version::V1 | Version::V2 => expand_olm(&self.0),
            Version::Interolm(..) => expand_olm(&self.0),
        }
    }
}

impl Shared3DHSecret {
    pub(crate) fn new(
        config: &SessionConfig,
        identity_key: &StaticSecret,
        base_key: &ReusableSecret,
        remote_identity_key: &PublicKey,
        remote_signed_prekey: &PublicKey,
        remote_one_time_key: Option<&PublicKey>,
    ) -> Self {
        let first_secret = identity_key.diffie_hellman(remote_signed_prekey);
        let second_secret = base_key.diffie_hellman(&remote_identity_key.inner);
        let third_secret = base_key.diffie_hellman(&remote_signed_prekey.inner);
        let fourth_secret = remote_one_time_key.map(|otk| base_key.diffie_hellman(&otk.inner));

        match config.version {
            Version::V1 | Version::V2 => {
                Self(merge_secrets_olm(first_secret, second_secret, third_secret))
            }
            #[cfg(feature = "interolm")]
            Version::Interolm(..) => {
                Self(merge_secrets_x3dh(first_secret, second_secret, third_secret, fourth_secret))
            }
        }
    }

    /// Expands secret input derived from the (X)3DH handshake into a root key
    /// and chain key.
    pub fn expand(self, config: &SessionConfig) -> (Box<[u8; 32]>, Box<[u8; 32]>) {
        match config.version {
            Version::V1 | Version::V2 => expand_olm(&self.0),
            Version::Interolm(..) => expand_olm(&self.0),
        }
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use x25519_dalek::ReusableSecret;

    use super::{RemoteShared3DHSecret, Shared3DHSecret};
    use crate::{
        olm::SessionConfig, types::Curve25519SecretKey as StaticSecret,
        Curve25519PublicKey as PublicKey,
    };

    #[test]
    fn triple_diffie_hellman() {
        let rng = thread_rng();
        let config = SessionConfig::default();

        let alice_identity = StaticSecret::new();
        let alice_one_time = ReusableSecret::random_from_rng(rng);

        let bob_identity = StaticSecret::new();
        let bob_one_time = StaticSecret::new();

        let alice_secret = Shared3DHSecret::new(
            &config,
            &alice_identity,
            &alice_one_time,
            &PublicKey::from(&bob_identity),
            &PublicKey::from(&bob_one_time),
            None,
        );

        let bob_secret = RemoteShared3DHSecret::new(
            &config,
            &bob_identity,
            &bob_one_time,
            None,
            &PublicKey::from(&alice_identity),
            &PublicKey::from(&alice_one_time),
        );

        assert_eq!(alice_secret.0, bob_secret.0);

        let alice_result = alice_secret.expand(&config);
        let bob_result = bob_secret.expand(&config);

        assert_eq!(alice_result, bob_result);
    }
}
