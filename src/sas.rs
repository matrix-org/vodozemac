// Copyright 2021 Damir Jelić, Denis Kasak
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
use hmac::{digest::MacError, Hmac, Mac};
use rand::thread_rng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, SharedSecret};
use thiserror::Error;

use crate::{
    utilities::{base64_decode, base64_encode},
    Curve25519KeyError, Curve25519PublicKey,
};

type HmacSha256Key = [u8; 32];

#[derive(Debug, Error)]
pub enum SasError {
    #[error("The SAS MAC wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("The SAS MAC validation didn't succeed: {0}")]
    Mac(#[from] MacError),
}

pub struct Sas {
    secret_key: EphemeralSecret,
    public_key: Curve25519PublicKey,
    encoded_public_key: String,
}

pub struct EstablishedSas {
    shared_secret: SharedSecret,
}

impl Default for Sas {
    fn default() -> Self {
        Self::new()
    }
}

impl Sas {
    pub fn new() -> Self {
        let rng = thread_rng();

        let secret_key = EphemeralSecret::new(rng);
        let public_key = Curve25519PublicKey::from(&secret_key);
        let encoded_public_key = base64_encode(public_key.as_bytes());

        Self { secret_key, public_key, encoded_public_key }
    }

    pub fn public_key(&self) -> &Curve25519PublicKey {
        &self.public_key
    }

    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }

    /// Establishes a SAS secret by performing a DH handshake with another
    /// public key.
    pub fn diffie_hellman(self, other_public_key: Curve25519PublicKey) -> EstablishedSas {
        let shared_secret = self.secret_key.diffie_hellman(&other_public_key.inner);

        EstablishedSas { shared_secret }
    }

    /// Establishes a SAS secret by performing a DH handshake with another
    /// public key in "raw", base64-encoded form.
    pub fn diffie_hellman_with_raw(
        self,
        other_public_key: &str,
    ) -> Result<EstablishedSas, Curve25519KeyError> {
        let other_public_key = Curve25519PublicKey::from_base64(other_public_key)?;

        let shared_secret = self.secret_key.diffie_hellman(&other_public_key.inner);

        Ok(EstablishedSas { shared_secret })
    }
}

impl EstablishedSas {
    fn get_hkdf(&self) -> Hkdf<Sha256> {
        Hkdf::new(None, self.shared_secret.as_bytes())
    }

    pub fn get_bytes(&self, info: &str, count: usize) -> Vec<u8> {
        let mut output = vec![0u8; count];
        let hkdf = self.get_hkdf();

        hkdf.expand(info.as_bytes(), &mut output[0..count]).expect("Can't generate the SAS bytes");

        output
    }

    fn get_mac_key(&self, info: &str) -> HmacSha256Key {
        let mut mac_key = [0u8; 32];
        let hkdf = self.get_hkdf();

        hkdf.expand(info.as_bytes(), &mut mac_key).expect("Can't expand the MAC key");

        mac_key
    }

    fn get_mac(&self, info: &str) -> Hmac<Sha256> {
        let mac_key = self.get_mac_key(info);
        Hmac::<Sha256>::new_from_slice(&mac_key).expect("Can't create a HMAC object")
    }

    pub fn calculate_mac(&self, input: &str, info: &str) -> String {
        let mut mac = self.get_mac(info);

        mac.update(input.as_ref());

        base64_encode(mac.finalize().into_bytes())
    }

    pub fn verify_mac(&self, input: &str, info: &str, tag: &str) -> Result<(), SasError> {
        let tag = base64_decode(tag)?;

        let mut mac = self.get_mac(info);
        mac.update(input.as_bytes());

        Ok(mac.verify_slice(&tag)?)
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use olm_rs::sas::OlmSas;

    use super::Sas;

    #[test]
    fn generate_bytes() -> Result<()> {
        let mut olm = OlmSas::new();
        let dalek = Sas::new();

        olm.set_their_public_key(dalek.public_key_encoded().to_string())
            .expect("Couldn't set the public key for libolm");
        let established = dalek.diffie_hellman_with_raw(&olm.public_key())?;

        assert_eq!(
            olm.generate_bytes("TEST", 10).expect("libolm coulnd't generate SAS bytes"),
            established.get_bytes("TEST", 10)
        );

        Ok(())
    }

    #[test]
    // Allowed to fail due to https://gitlab.matrix.org/matrix-org/olm/-/merge_requests/16
    fn calculate_mac() -> Result<()> {
        let mut olm = OlmSas::new();
        let dalek = Sas::new();

        olm.set_their_public_key(dalek.public_key_encoded().to_string())
            .expect("Couldn't set the public key for libolm");
        let established = dalek.diffie_hellman_with_raw(&olm.public_key())?;

        let olm_mac = olm.calculate_mac("", "").expect("libolm couldn't calculate a MAC");
        assert_eq!(olm_mac, established.calculate_mac("", ""));

        established.verify_mac("", "", olm_mac.as_str())?;

        Ok(())
    }
}
