//! XEdDSA signing algorithm implementation
//!
//! Reference: <https://signal.org/docs/specifications/xeddsa/#xeddsa>

use std::fmt::Debug;

use rand::thread_rng;
use thiserror::Error;
use xeddsa::{
    xed25519::{PrivateKey, PublicKey},
    xeddsa::Error as XEdDsaError,
    Sign, Verify,
};

use crate::utilities::{base64_decode, base64_encode};

pub const SIGNATURE_LENGTH: usize = 64;

const CURVE25519_PUBLIC_KEY_LENGTH: usize = 32;
const CURVE25519_SECRET_KEY_LENGTH: usize = 32;

/// An XEdDSA digital signature, can be used to verify the authenticity of a
/// message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XEdDsaSignature(pub(crate) [u8; SIGNATURE_LENGTH]);

impl XEdDsaSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_base64(signature: &str) -> Result<Self, SignatureError> {
        base64_decode(signature)?.as_slice().try_into()
    }

    pub fn to_base64(&self) -> String {
        base64_encode(self.0)
    }
}

impl TryFrom<&[u8]> for XEdDsaSignature {
    type Error = SignatureError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let signature: [u8; SIGNATURE_LENGTH] =
            value.try_into().map_err(|_| SignatureError::InvalidSignatureLength(value.len()))?;
        Ok(Self(signature))
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for XEdDsaSignature {
    fn from(value: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(value)
    }
}

impl Debug for XEdDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("XEdDSASignature").field(&self.to_base64()).finish()
    }
}

impl Verify<XEdDsaSignature, [u8; 32]> for PublicKey {
    fn verify(&self, message: &[u8], signature: &XEdDsaSignature) -> Result<(), xeddsa::Error> {
        self.verify(message, &signature.0)
    }
}

/// Error type describing XEdDSA signature verification failures.
#[cfg(feature = "interolm")]
#[derive(Debug, Error)]
pub enum SignatureError {
    /// The signature wasn't valid base64.
    #[error("The signature couldn't be decoded: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The decoded signature was of invalid length.
    #[error("The signature has an invalid length: expected {}, got {0}", SIGNATURE_LENGTH)]
    InvalidSignatureLength(usize),
    /// The signature failed to be verified.
    #[error("The signature was decoded successfully but is invalid.")]
    InvalidSignature(#[from] XEdDsaError),
}

pub(crate) fn sign(key: &[u8; CURVE25519_SECRET_KEY_LENGTH], message: &[u8]) -> XEdDsaSignature {
    let key = PrivateKey(*key);
    let rng = thread_rng();
    let result = key.sign(message, rng);
    XEdDsaSignature(result)
}

pub(crate) fn verify(
    public_key: &[u8; CURVE25519_PUBLIC_KEY_LENGTH],
    message: &[u8],
    signature: XEdDsaSignature,
) -> Result<(), SignatureError> {
    let key = PublicKey(*public_key);

    match key.verify(message, &signature) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod test {
    use super::{sign, verify};
    use crate::{
        types::{Curve25519Keypair, Curve25519SecretKey},
        Curve25519PublicKey, XEdDsaSignature,
    };

    #[test]
    pub fn test_signature_verification() {
        let message = "sahasrahla";
        let key_pair = Curve25519Keypair::new();

        let signature = sign(&key_pair.secret_key().to_bytes(), message.as_bytes());

        verify(key_pair.public_key().as_bytes(), message.as_bytes(), signature)
            .expect("The signature should be valid");

        let corrupted_message = message.to_owned() + "!";

        verify(key_pair.public_key().as_bytes(), corrupted_message.as_bytes(), signature)
            .expect_err("The signature should be invalid");

        let mut corrupted_signature = signature;
        corrupted_signature.0[0] += 1;
        verify(key_pair.public_key().as_bytes(), message.as_bytes(), corrupted_signature)
            .expect_err("The signature should be invalid");
    }

    #[test]
    pub fn test_known_signature() {
        let message = "sahasrahla";
        let secret_key = [
            219, 209, 232, 97, 65, 93, 1, 89, 16, 37, 173, 21, 224, 61, 51, 34, 114, 154, 249, 245,
            60, 88, 187, 216, 102, 250, 99, 184, 106, 38, 33, 139,
        ];
        let signing_key = Curve25519SecretKey::from_slice(&secret_key);
        let verification_key = Curve25519PublicKey::from(&signing_key);

        let signature = XEdDsaSignature([
            10, 129, 186, 162, 96, 123, 226, 104, 147, 200, 65, 38, 35, 123, 77, 4, 195, 122, 160,
            107, 135, 83, 121, 191, 226, 9, 240, 208, 100, 126, 206, 81, 243, 31, 78, 56, 246, 235,
            244, 199, 40, 178, 96, 72, 138, 96, 47, 205, 234, 107, 101, 79, 121, 125, 178, 46, 142,
            215, 145, 247, 221, 235, 220, 3,
        ]);

        verify(verification_key.as_bytes(), message.as_bytes(), signature)
            .expect("The known signature should be valid.");
    }
}
