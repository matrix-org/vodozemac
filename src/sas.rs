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

//! User-friendly key verification using short authentication strings (SAS).
//!
//! The verification process is heavily inspired by Phil Zimmermann’s [ZRTP]
//! key agreement handshake. A core part of key agreement in [ZRTP] is the
//! *hash commitment*: the party that begins the key sharing process sends
//! a *hash* of their part of the Diffie-Hellman exchange but does not send the
//! part itself exchange until they had received the other party’s part.
//!
//! The verification process can be used to verify the Ed25519 identity key of
//! an [`Account`].
//!
//! # Examples
//!
//! ```rust
//! use vodozemac::sas::Sas;
//! # use anyhow::Result;
//! # fn main() -> Result<()> {
//! let alice = Sas::new();
//! let bob = Sas::new();
//!
//! let bob_public_key = bob.public_key();
//!
//! let bob = bob.diffie_hellman(alice.public_key())?;
//! let alice = alice.diffie_hellman(bob_public_key)?;
//!
//! let alice_bytes = alice.bytes("AGREED_INFO");
//! let bob_bytes = bob.bytes("AGREED_INFO");
//!
//! let alice_emojis = alice_bytes.emoji_indices();
//! let bob_emojis = bob_bytes.emoji_indices();
//!
//! assert_eq!(alice_emojis, bob_emojis);
//! # Ok(())
//! # }
//! ```
//!
//! [`Account`]: crate::olm::Account
//! [ZRTP]: https://tools.ietf.org/html/rfc6189#section-4.4.1

use hkdf::Hkdf;
use hmac::{digest::MacError, Hmac, Mac as _};
use rand::thread_rng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, SharedSecret};

use crate::{
    utilities::{base64_decode, base64_encode},
    Curve25519PublicKey, PublicKeyError,
};

type HmacSha256Key = [u8; 32];

/// The output type for the SAS MAC calculation.
pub struct Mac(Vec<u8>);

impl Mac {
    /// Convert the MAC to a base64 encoded string.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.0)
    }

    /// Get the byte slice of the MAC.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a new `Mac` object from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Create a new `Mac` object from a base64 encoded string.
    pub fn from_base64(mac: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64_decode(mac)?;

        Ok(Self(bytes))
    }
}

/// Error type for the case when we try to generate too many SAS bytes.
#[derive(Debug, Clone, Error)]
#[error("The given count of bytes was too large")]
pub struct InvalidCount;

/// Error type describing failures that can happen during the key verification.
#[derive(Debug, Error)]
pub enum SasError {
    /// The MAC failed to be validated.
    #[error("The SAS MAC validation didn't succeed: {0}")]
    Mac(#[from] MacError),
}

/// A struct representing a short auth string verification object.
///
/// This object can be used to establish a shared secret to perform the short
/// auth string based key verification.
pub struct Sas {
    secret_key: EphemeralSecret,
    public_key: Curve25519PublicKey,
    encoded_public_key: String,
}

/// A struct representing a short auth string verification object where the
/// shared secret has been established.
///
/// This object can be used to generate the short auth string and calculate and
/// verify a MAC that protects information about the keys being verified.
pub struct EstablishedSas {
    shared_secret: SharedSecret,
    our_public_key: Curve25519PublicKey,
    their_public_key: Curve25519PublicKey,
}

impl std::fmt::Debug for EstablishedSas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedSas")
            .field("our_public_key", &self.our_public_key.to_base64())
            .field("their_public_key", &self.their_public_key.to_base64())
            .finish_non_exhaustive()
    }
}

/// Bytes generated from an shared secret that can be used as the short auth
/// string.
#[derive(Debug, Clone, PartialEq)]
pub struct SasBytes {
    bytes: [u8; 6],
}

impl SasBytes {
    /// Get the index of 7 emojis that can be presented to users to perform the
    /// key verification
    ///
    /// The table that maps the index to an emoji can be found in the [spec].
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji
    pub fn emoji_indices(&self) -> [u8; 7] {
        Self::bytes_to_emoji_index(&self.bytes)
    }

    /// Get the three decimal numbers that can be presented to users to perform
    /// the key verification, as described in the [spec]
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji
    pub fn decimals(&self) -> (u16, u16, u16) {
        Self::bytes_to_decimal(&self.bytes)
    }

    /// Get the raw bytes of the short auth string that can be converted to an
    /// emoji, or decimal representation.
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.bytes
    }

    /// Split the first 42 bits of our 6 bytes into 7 groups of 6 bits. The 7
    /// groups of 6 bits represent an emoji index from the [spec].
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#sas-method-emoji
    fn bytes_to_emoji_index(bytes: &[u8; 6]) -> [u8; 7] {
        let bytes: Vec<u64> = bytes.iter().map(|b| *b as u64).collect();
        // Join the 6 bytes into one 64 bit unsigned int. This u64 will contain 48
        // bits from our 6 bytes.
        let mut num: u64 = bytes[0] << 40;
        num += bytes[1] << 32;
        num += bytes[2] << 24;
        num += bytes[3] << 16;
        num += bytes[4] << 8;
        num += bytes[5];

        // Take the top 42 bits of our 48 bits from the u64 and convert each 6 bits
        // into a 6 bit number.
        [
            ((num >> 42) & 63) as u8,
            ((num >> 36) & 63) as u8,
            ((num >> 30) & 63) as u8,
            ((num >> 24) & 63) as u8,
            ((num >> 18) & 63) as u8,
            ((num >> 12) & 63) as u8,
            ((num >> 6) & 63) as u8,
        ]
    }

    /// Convert the given bytes into three decimals. The 6th byte is ignored,
    /// it's used for the emoji index conversion.
    fn bytes_to_decimal(bytes: &[u8; 6]) -> (u16, u16, u16) {
        let bytes: Vec<u16> = bytes.iter().map(|b| *b as u16).collect();

        // This bitwise operation is taken from the [spec]
        // [spec]: https://matrix.org/docs/spec/client_server/latest#sas-method-decimal
        let first = bytes[0] << 5 | bytes[1] >> 3;
        let second = (bytes[1] & 0x7) << 10 | bytes[2] << 2 | bytes[3] >> 6;
        let third = (bytes[3] & 0x3F) << 7 | bytes[4] >> 1;

        (first + 1000, second + 1000, third + 1000)
    }
}

impl Default for Sas {
    fn default() -> Self {
        Self::new()
    }
}

impl Sas {
    /// Create a new random verification object
    ///
    /// This creates an ephemeral curve25519 keypair that can be used to
    /// establish a shared secret.
    pub fn new() -> Self {
        let rng = thread_rng();

        let secret_key = EphemeralSecret::new(rng);
        let public_key = Curve25519PublicKey::from(&secret_key);
        let encoded_public_key = base64_encode(public_key.as_bytes());

        Self { secret_key, public_key, encoded_public_key }
    }

    /// Get the public key that can be used to establish a shared secret.
    pub fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }

    /// Get the public key as a base64 encoded string.
    pub fn public_key_encoded(&self) -> &str {
        &self.encoded_public_key
    }

    /// Establishes a SAS secret by performing a DH handshake with another
    /// public key.
    ///
    /// Returns an [`EstablishedSas`] object which can be used to generate
    /// [`SasBytes`] if the given public key was valid, otherwise `None`.
    pub fn diffie_hellman(
        self,
        their_public_key: Curve25519PublicKey,
    ) -> Result<EstablishedSas, PublicKeyError> {
        let shared_secret = self.secret_key.diffie_hellman(&their_public_key.inner);

        if shared_secret.was_contributory() {
            Ok(EstablishedSas { shared_secret, our_public_key: self.public_key, their_public_key })
        } else {
            Err(PublicKeyError::NonContributoryKey)
        }
    }

    /// Establishes a SAS secret by performing a DH handshake with another
    /// public key in "raw", base64-encoded form.
    ///
    /// Returns an [`EstablishedSas`] object which can be used to generate
    /// [`SasBytes`] if the received public key is valid, otherwise `None`.
    pub fn diffie_hellman_with_raw(
        self,
        other_public_key: &str,
    ) -> Result<EstablishedSas, PublicKeyError> {
        let other_public_key = Curve25519PublicKey::from_base64(other_public_key)?;
        self.diffie_hellman(other_public_key)
    }
}

impl EstablishedSas {
    /// Generate [`SasBytes`] using HKDF with the shared secret as the input key
    /// material.
    ///
    /// The info string should be agreed upon beforehand, both parties need to
    /// use the same info string.
    pub fn bytes(&self, info: &str) -> SasBytes {
        let mut bytes = [0u8; 6];
        let byte_vec = self.bytes_raw(info, 6).expect("HKDF can always generate 6 bytes");

        bytes.copy_from_slice(&byte_vec);

        SasBytes { bytes }
    }

    /// Generate the given number  of bytes using HKDF with the shared secret
    /// as the input key material.
    ///
    /// The info string should be agreed upon beforehand, both parties need to
    /// use the same info string.
    ///
    /// The number of bytes we can generate is limited, we can generate up to
    /// 32 * 255 bytes. The function will not fail if the given count is smaller
    /// than the limit.
    pub fn bytes_raw(&self, info: &str, count: usize) -> Result<Vec<u8>, InvalidCount> {
        let mut output = vec![0u8; count];
        let hkdf = self.get_hkdf();

        hkdf.expand(info.as_bytes(), &mut output[0..count]).map_err(|_| InvalidCount)?;

        Ok(output)
    }

    /// Calculate a MAC for the given input using the info string as additional
    /// data.
    ///
    ///
    /// This should be used to calculate a MAC of the ed25519 identity key of an
    /// [`Account`]
    ///
    /// The MAC is returned as a base64 encoded string.
    ///
    /// [`Account`]: crate::olm::Account
    pub fn calculate_mac(&self, input: &str, info: &str) -> Mac {
        let mut mac = self.get_mac(info);

        mac.update(input.as_ref());

        Mac(mac.finalize().into_bytes().to_vec())
    }

    /// Calculate a MAC for the given input using the info string as additional
    /// data, the MAC is returned as an invalid base64 encoded string.
    ///
    /// **Warning**: This method should never be used unless you require libolm
    /// compatibility. Libolm used to incorrectly encode their MAC because the
    /// input buffer was reused as the output buffer. This method replicates the
    /// buggy behaviour.
    #[cfg(feature = "libolm-compat")]
    pub fn calculate_mac_invalid_base64(&self, input: &str, info: &str) -> String {
        // First calculate the MAC as usual.
        let mac = self.calculate_mac(input, info);

        // Since the input buffer is reused as an output buffer, and base64
        // operates on 3 input bytes to generate 4 output bytes, the input
        // buffer gets overrun by the output.
        //
        // Only 6 bytes of the MAC get to be used before the output overwrites
        // the input.

        // All three bytes of the first input chunk are used successfully.
        let mut out = base64_encode(&mac.as_bytes()[0..3]);

        // For the next input chunk, only two bytes are sourced from the actual
        // MAC, since the first byte gets overwritten by the output.
        let mut bytes_from_mac = 2;

        // Subsequent input chunks get progressively more overwritten by the
        // output, so that after two iterations, none of the original input
        // bytes remain.
        for i in (6..10).step_by(3) {
            let from_mac = &mac.as_bytes()[i - bytes_from_mac..i];
            let from_out = &out.as_bytes()[out.len() - (3 - bytes_from_mac)..];

            let bytes = [from_out, from_mac].concat();
            let encoded = base64_encode(bytes);
            bytes_from_mac -= 1;

            out = out + &encoded;
        }

        // At this point, the rest of our input will be completely sourced from
        // the previous output. The MAC has a size of 32, so we abort before we
        // get to the remainder calculation.
        for i in (9..30).step_by(3) {
            let next = &out.as_bytes()[i..i + 3];
            let next_four = base64_encode(next);
            out = out + &next_four;
        }

        // Finally, use the remainder to get the last 3 bytes of output. No
        // padding is used.
        let next = &out.as_bytes()[30..32];
        let next = base64_encode(next);

        out + &next
    }

    /// Verify a MAC that was previously created using the
    /// [`EstablishedSas::calculate_mac()`] method.
    ///
    /// Users should calculate a MAC and send it to the other side, they should
    /// then verify each other's MAC using this method.
    pub fn verify_mac(&self, input: &str, info: &str, tag: &Mac) -> Result<(), SasError> {
        let mut mac = self.get_mac(info);
        mac.update(input.as_bytes());

        Ok(mac.verify_slice(&tag.0)?)
    }

    /// Get the public key that was created by us, that was used to establish
    /// the shared secret.
    pub fn our_public_key(&self) -> Curve25519PublicKey {
        self.our_public_key
    }

    /// Get the public key that was created by the other party, that was used to
    /// establish the shared secret.
    pub fn their_public_key(&self) -> Curve25519PublicKey {
        self.their_public_key
    }

    fn get_hkdf(&self) -> Hkdf<Sha256> {
        Hkdf::new(None, self.shared_secret.as_bytes())
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
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use olm_rs::sas::OlmSas;
    use proptest::prelude::*;

    use super::{Mac, Sas, SasBytes};

    #[test]
    fn generate_bytes() -> Result<()> {
        let mut olm = OlmSas::new();
        let dalek = Sas::new();

        olm.set_their_public_key(dalek.public_key_encoded().to_string())
            .expect("Couldn't set the public key for libolm");
        let established = dalek.diffie_hellman_with_raw(&olm.public_key())?;

        assert_eq!(
            olm.generate_bytes("TEST", 10).expect("libolm coulnd't generate SAS bytes"),
            established.bytes_raw("TEST", 10)?
        );

        Ok(())
    }

    #[test]
    fn calculate_mac() -> Result<()> {
        let alice_on_dalek = Sas::new();
        let mut bob_on_libolm = OlmSas::new();

        let alice_mxid = "@alice:example.com";
        let alice_device_id = "AAAAAAAAAA";
        let alice_public_key = alice_on_dalek.public_key_encoded();
        let bob_mxid = "@bob:example.com";
        let bob_device_id = "BBBBBBBBBB";
        let bob_public_key = bob_on_libolm.public_key();

        let message = format!("ed25519:{}", bob_device_id);
        let extra_info = format!(
            "{}{}{}{}{}{}{}",
            "MATRIX_KEY_VERIFICATION_MAC",
            bob_mxid,
            bob_device_id,
            alice_mxid,
            alice_device_id,
            "$1234567890",
            "KEY_IDS"
        );

        bob_on_libolm
            .set_their_public_key(alice_public_key.to_string())
            .expect("Couldn't set the public key for libolm");
        let established = alice_on_dalek.diffie_hellman_with_raw(&bob_public_key)?;

        let olm_mac = bob_on_libolm
            .calculate_mac_fixed_base64(&message, &extra_info)
            .expect("libolm couldn't calculate a MAC");
        assert_eq!(olm_mac, established.calculate_mac(&message, &extra_info).to_base64());

        let olm_mac = Mac::from_base64(&olm_mac).expect("Olm MAC wasn't valid base64");

        established.verify_mac(&message, &extra_info, &olm_mac)?;

        Ok(())
    }

    #[test]
    fn calculate_mac_invalid_base64() -> Result<()> {
        let mut olm = OlmSas::new();
        let dalek = Sas::new();

        olm.set_their_public_key(dalek.public_key_encoded().to_string())
            .expect("Couldn't set the public key for libolm");
        let established = dalek.diffie_hellman_with_raw(&olm.public_key())?;

        let olm_mac = olm.calculate_mac("", "").expect("libolm couldn't calculate a MAC");
        assert_eq!(olm_mac, established.calculate_mac_invalid_base64("", ""));

        Ok(())
    }

    #[test]
    fn emoji_generation() {
        let bytes: [u8; 6] = [0, 0, 0, 0, 0, 0];
        let index: [u8; 7] = [0, 0, 0, 0, 0, 0, 0];
        assert_eq!(SasBytes::bytes_to_emoji_index(&bytes), index.as_ref());

        let bytes: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let index: [u8; 7] = [63, 63, 63, 63, 63, 63, 63];
        assert_eq!(SasBytes::bytes_to_emoji_index(&bytes), index.as_ref());
    }

    #[test]
    fn decimal_generation() {
        let bytes: [u8; 6] = [0, 0, 0, 0, 0, 0];
        let result = SasBytes::bytes_to_decimal(&bytes);

        assert_eq!(result, (1000, 1000, 1000));

        let bytes: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = SasBytes::bytes_to_decimal(&bytes);
        assert_eq!(result, (9191, 9191, 9191));
    }

    proptest! {
        #[test]
        fn proptest_emoji(bytes in prop::array::uniform6(0u8..)) {
            let numbers = SasBytes::bytes_to_emoji_index(&bytes);

            for number in numbers.iter() {
                prop_assert!(*number < 64);
            }
        }
    }

    proptest! {
        #[test]
        fn proptest_decimals(bytes in prop::array::uniform6(0u8..)) {
            let (first, second, third) = SasBytes::bytes_to_decimal(&bytes);

            prop_assert!((1000..=9191).contains(&first));
            prop_assert!((1000..=9191).contains(&second));
            prop_assert!((1000..=9191).contains(&third));
        }
    }
}
