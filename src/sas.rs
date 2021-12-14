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

#![allow(dead_code)]

use hkdf::Hkdf;
use hmac::{digest::MacError, Hmac, Mac};
use rand::thread_rng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::utilities::{decode, encode};

pub struct Sas {
    secret_key: EphemeralSecret,
    public_key: PublicKey,
    encoded_public_key: String,
}

pub struct EstablishedSas {
    shared_secret: SharedSecret,
    public_key: PublicKey,
    encoded_public_key: String,
}

impl Sas {
    pub fn new() -> Self {
        let rng = thread_rng();

        let secret_key = EphemeralSecret::new(rng);
        let public_key = PublicKey::from(&secret_key);
        let encoded_public_key = encode(public_key.as_bytes());

        Self { secret_key, public_key, encoded_public_key }
    }

    pub fn public_key(&self) -> &str {
        &self.encoded_public_key
    }

    pub fn diffie_hellman(self, other_public_key: String) -> EstablishedSas {
        let mut public_key = [0u8; 32];
        // TODO check the length of the key.
        public_key.copy_from_slice(&decode(other_public_key.as_bytes()).unwrap());
        let public_key = PublicKey::from(public_key);
        let shared_secret = self.secret_key.diffie_hellman(&public_key);

        EstablishedSas {
            shared_secret,
            public_key: self.public_key,
            encoded_public_key: self.encoded_public_key,
        }
    }
}

impl EstablishedSas {
    pub fn get_bytes(&self, info: &str, count: usize) -> Vec<u8> {
        let hkdf: Hkdf<Sha256> = Hkdf::new(None, self.shared_secret.as_bytes());
        let mut output = vec![0u8; count];
        hkdf.expand(info.as_bytes(), &mut output[0..count]).unwrap();

        output
    }

    pub fn calculate_mac(&self, input: &str, info: &str) -> String {
        let mut mac_key = [0u8; 32];
        let hkdf: Hkdf<Sha256> = Hkdf::new(None, self.shared_secret.as_bytes());
        hkdf.expand(info.as_bytes(), &mut mac_key).unwrap();

        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        mac.update(input.as_ref());

        let output = mac.finalize().into_bytes();
        encode(output)
    }

    pub fn verify_mac(&self, input: &str, info: &str, code: &str) -> Result<(), MacError> {
        let mut mac_key = [0u8; 32];
        let hkdf: Hkdf<Sha256> = Hkdf::new(None, self.shared_secret.as_bytes());
        hkdf.expand(info.as_bytes(), &mut mac_key).unwrap();

        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        mac.update(input.as_bytes());
        let code = decode(code).unwrap();
        mac.verify_slice(&code)
    }
}

#[cfg(test)]
mod test {
    use olm_rs::sas::OlmSas;

    use super::Sas;

    #[test]
    fn generate_bytes() {
        let mut olm = OlmSas::new();
        let dalek = Sas::new();

        olm.set_their_public_key(dalek.public_key().to_string()).unwrap();
        let established = dalek.diffie_hellman(olm.public_key());

        assert_eq!(olm.generate_bytes("TEST", 10).unwrap(), established.get_bytes("TEST", 10));
    }

    #[test]
    fn calculate_mac() {
        let mut olm = OlmSas::new();
        let dalek = Sas::new();

        olm.set_their_public_key(dalek.public_key().to_string()).unwrap();
        let established = dalek.diffie_hellman(olm.public_key());

        assert_eq!(olm.calculate_mac("", "").unwrap(), established.calculate_mac("", ""));

        let olm_mac = olm.calculate_mac("", "").unwrap();

        established.verify_mac("", "", olm_mac.as_str()).unwrap()
    }
}
