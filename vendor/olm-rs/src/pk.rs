// Copyright 2020 The Matrix.org Foundation C.I.C.
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

//! This module wraps around all functions following the pattern `olm_pk_*`.

use std::ffi::CStr;

use zeroize::Zeroizing;

use crate::errors::{self, OlmPkDecryptionError, OlmPkEncryptionError, OlmPkSigningError};
use crate::{getrandom, ByteBuf, PicklingMode};

/// A PK encrypted message.
pub struct PkMessage {
    pub ciphertext: String,
    pub mac: String,
    pub ephemeral_key: String,
}

impl PkMessage {
    /// Create a new PK encrypted message.
    ///
    /// # Arguments
    ///
    /// * `ephemeral_key` - the public part of the ephemeral key used (together
    /// with the recipient's key) to generate a symmetric encryption key.
    ///
    /// * `mac` - Message Authentication Code of the encrypted message
    ///
    /// * `ciphertext` - The cipher text of the encrypted message
    pub fn new(ephemeral_key: String, mac: String, ciphertext: String) -> Self {
        PkMessage {
            ciphertext,
            mac,
            ephemeral_key,
        }
    }
}

/// The encryption part of a PK encrypted channel.
pub struct OlmPkEncryption {
    ptr: *mut olm_sys::OlmPkEncryption,
    _buf: ByteBuf,
}

impl Drop for OlmPkEncryption {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_pk_encryption(self.ptr);
        }
    }
}

impl Default for OlmPkDecryption {
    fn default() -> Self {
        Self::new()
    }
}

impl OlmPkEncryption {
    /// Create a new PK encryption object.
    ///
    /// # Arguments
    ///
    /// * `recipient_key` - a public key that will be used for encryption, the
    ///     public key will be provided by the matching decryption object.
    pub fn new(recipient_key: &str) -> Self {
        let mut buf = ByteBuf::new(unsafe { olm_sys::olm_pk_encryption_size() });
        let ptr = unsafe { olm_sys::olm_pk_encryption(buf.as_mut_void_ptr()) };

        unsafe {
            olm_sys::olm_pk_encryption_set_recipient_key(
                ptr,
                recipient_key.as_ptr() as *mut _,
                recipient_key.len(),
            );
        }

        Self { ptr, _buf: buf }
    }

    fn last_error(ptr: *mut olm_sys::OlmPkEncryption) -> OlmPkEncryptionError {
        let error = unsafe {
            let error_raw = olm_sys::olm_pk_encryption_last_error(ptr);
            CStr::from_ptr(error_raw).to_str().unwrap()
        };
        error.into()
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the encrypted PkMessage.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - A string that will be encrypted using the PkEncryption
    ///     object.
    ///
    /// # Panics
    /// * `InputBufferTooSmall` if the ciphertext, ephemeral key, or  mac
    /// buffers are too small.
    /// * `OutputBufferTooSmall` if the random buffer is too small.
    /// * on malformed UTF-8 coding of the ciphertext provided by libolm
    pub fn encrypt(&self, plaintext: &str) -> PkMessage {
        let random_length = unsafe { olm_sys::olm_pk_encrypt_random_length(self.ptr) };

        let mut random_buf = Zeroizing::new(vec![0; random_length]);
        getrandom(&mut random_buf);

        let ciphertext_length =
            unsafe { olm_sys::olm_pk_ciphertext_length(self.ptr, plaintext.len()) };

        let mac_length = unsafe { olm_sys::olm_pk_mac_length(self.ptr) };

        let ephemeral_key_size = unsafe { olm_sys::olm_pk_key_length() };

        let mut ciphertext = vec![0; ciphertext_length];
        let mut mac = vec![0; mac_length];
        let mut ephemeral_key = vec![0; ephemeral_key_size];

        let ret = unsafe {
            olm_sys::olm_pk_encrypt(
                self.ptr,
                plaintext.as_ptr() as *const _,
                plaintext.len(),
                ciphertext.as_mut_ptr() as *mut _,
                ciphertext.len(),
                mac.as_mut_ptr() as *mut _,
                mac.len(),
                ephemeral_key.as_mut_ptr() as *mut _,
                ephemeral_key.len(),
                random_buf.as_ptr() as *mut _,
                random_buf.len(),
            )
        };

        if ret == errors::olm_error() {
            errors::handle_fatal_error(OlmPkEncryption::last_error(self.ptr));
        }

        let ciphertext = unsafe { String::from_utf8_unchecked(ciphertext) };
        let mac = unsafe { String::from_utf8_unchecked(mac) };
        let ephemeral_key = unsafe { String::from_utf8_unchecked(ephemeral_key) };

        PkMessage {
            ciphertext,
            mac,
            ephemeral_key,
        }
    }
}

/// The decryption part of a PK encrypted channel.
pub struct OlmPkDecryption {
    ptr: *mut olm_sys::OlmPkDecryption,
    _buf: ByteBuf,
    public_key: String,
}

impl Drop for OlmPkDecryption {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_pk_decryption(self.ptr);
        }
    }
}

impl OlmPkDecryption {
    /// Create a new PK decryption object initializing the private key to a
    /// random value.
    ///
    /// # Panics
    /// * `NOT_ENOUGH_RANDOM` if there's not enough random data provided when
    /// creating the OlmPkDecryption object.
    /// * on malformed UTF-8 coding of the public key that is generated by
    /// libolm.
    pub fn new() -> Self {
        let random_len = Self::private_key_length();
        let mut random_buf = Zeroizing::new(vec![0; random_len]);
        getrandom(&mut random_buf);

        Self::from_bytes(&random_buf)
            .expect("Can't create a PK decryption object from a valid random key")
    }

    /// Get the number of bytes a private key needs to have.
    pub fn private_key_length() -> usize {
        unsafe { olm_sys::olm_pk_private_key_length() }
    }

    /// Create a new PK decryption object from the given private key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - An array of random bytes, the number of bytes this method
    /// expects can be checked using the [`OlmPkDecryption::private_key_length`]
    /// method.
    ///
    /// **Warning**: The caller needs to ensure that the passed in bytes are
    /// cryptographically sound.
    ///
    /// # Panics
    /// * on malformed UTF-8 coding of the public key that is generated by
    /// libolm.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OlmPkDecryptionError> {
        let (ptr, buf) = OlmPkDecryption::init();

        let key_length = unsafe { olm_sys::olm_pk_key_length() };
        let mut key_buffer = vec![0; key_length];

        let ret = unsafe {
            olm_sys::olm_pk_key_from_private(
                ptr,
                key_buffer.as_mut_ptr() as *mut _,
                key_buffer.len(),
                bytes.as_ptr() as *const _,
                bytes.len(),
            )
        };

        if ret == errors::olm_error() {
            Err(Self::last_error(ptr))
        } else {
            let public_key = String::from_utf8(key_buffer)
                .expect("Can't convert the public key buffer to a string");

            Ok(Self {
                ptr,
                _buf: buf,
                public_key,
            })
        }
    }

    fn init() -> (*mut olm_sys::OlmPkDecryption, ByteBuf) {
        let mut buf = ByteBuf::new(unsafe { olm_sys::olm_pk_decryption_size() });
        let ptr = unsafe { olm_sys::olm_pk_decryption(buf.as_mut_void_ptr() as *mut _) };

        (ptr, buf)
    }

    fn last_error(ptr: *mut olm_sys::OlmPkDecryption) -> OlmPkDecryptionError {
        let error = unsafe {
            let error_raw = olm_sys::olm_pk_decryption_last_error(ptr);
            CStr::from_ptr(error_raw).to_str().unwrap()
        };
        error.into()
    }

    /// Store a PkDecryption object.
    ///
    /// Stores a [`OlmPkDecryption`] object as a base64 string. Encrypts the object
    /// using the supplied passphrase. Returns a byte object containing the
    /// base64 encoded string of the pickled session.
    ///
    /// # Arguments
    ///
    /// * `mode` - The pickle mode that should be used to store the decryption
    /// object.
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for OlmSession's pickled buffer
    /// * on malformed UTF-8 coding of the pickling provided by libolm
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let mut pickled_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_pickle_pk_decryption_length(self.ptr) }];

        let pickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_pickle_pk_decryption(
                    self.ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_buf.len(),
                )
            }
        };

        let pickled_result =
            String::from_utf8(pickled_buf).expect("Pickle string is not valid utf-8");

        if pickle_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.ptr));
        }

        pickled_result
    }

    /// Restore a previously stored OlmPkDecryption object.
    ///
    /// Creates a [`OlmPkDecryption`] object from a pickled base64 string. Decrypts
    /// the pickled object using the supplied passphrase.
    ///
    /// # Arguments
    ///
    /// * `mode` - The pickle mode that should be used to store the decryption
    /// object.
    ///
    /// # C-API equivalent
    /// `olm_unpickle_pk_decryption`
    ///
    /// # Errors
    ///
    /// * `BadAccountKey` if the key doesn't match the one the account was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    /// # Panics
    ///
    /// * on malformed UTF-8 coding of the public key that is generated by
    /// libolm.
    pub fn unpickle(mut pickle: String, mode: PicklingMode) -> Result<Self, OlmPkDecryptionError> {
        let (ptr, buf) = OlmPkDecryption::init();

        let pubkey_length = unsafe { olm_sys::olm_pk_signing_public_key_length() };
        let mut pubkey_buffer = vec![0; pubkey_length];

        let unpickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_unpickle_pk_decryption(
                    ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickle.as_mut_ptr() as *mut _,
                    pickle.len(),
                    pubkey_buffer.as_mut_ptr() as *mut _,
                    pubkey_buffer.len(),
                )
            }
        };

        let public_key = String::from_utf8(pubkey_buffer)
            .expect("Can't conver the public key buffer to a string");

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(ptr))
        } else {
            Ok(Self {
                ptr,
                _buf: buf,
                public_key,
            })
        }
    }

    /// Decrypts a PK message using this decryption object.
    ///
    /// Decoding is lossy, meaing if the decrypted plaintext contains invalid
    /// UTF-8 symbols, they will be returned as `U+FFFD` (�).
    ///
    /// # Arguments
    ///
    /// * `message` - The encrypted PkMessage that should be decrypted.
    ///
    /// # C-API equivalent
    /// `olm_pk_decrypt`
    ///
    /// # Errors
    /// * `InvalidBase64` on invalid base64 coding for supplied arguments
    /// * `BadMessageVersion` on unsupported protocol version
    /// * `BadMessageFormat` on failing to decode the message
    /// * `BadMessageMac` on invalid message MAC
    ///
    /// # Panics
    ///
    /// * `OutputBufferTooSmall` on plaintext output buffer
    ///
    pub fn decrypt(&self, mut message: PkMessage) -> Result<String, OlmPkDecryptionError> {
        let max_plaintext = {
            let ret =
                unsafe { olm_sys::olm_pk_max_plaintext_length(self.ptr, message.ciphertext.len()) };

            if ret == errors::olm_error() {
                return Err(OlmPkDecryptionError::InvalidBase64);
            }

            ret
        };

        let mut plaintext = vec![0; max_plaintext];

        let plaintext_len = unsafe {
            olm_sys::olm_pk_decrypt(
                self.ptr,
                message.ephemeral_key.as_ptr() as *const _,
                message.ephemeral_key.len(),
                message.mac.as_ptr() as *const _,
                message.mac.len(),
                message.ciphertext.as_mut_ptr() as *mut _,
                message.ciphertext.len(),
                plaintext.as_mut_ptr() as *mut _,
                max_plaintext,
            )
        };

        if plaintext_len == errors::olm_error() {
            Err(Self::last_error(self.ptr))
        } else {
            plaintext.truncate(plaintext_len);
            Ok(String::from_utf8_lossy(&plaintext).to_string())
        }
    }

    /// Get the public key of the decryption object.
    ///
    /// This can be used to initialize a encryption object to encrypt messages
    /// for this decryption object.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

/// Signs messages using public key cryptography.
pub struct OlmPkSigning {
    ptr: *mut olm_sys::OlmPkSigning,
    _buf: ByteBuf,
    public_key: String,
}

impl Drop for OlmPkSigning {
    fn drop(&mut self) {
        unsafe { olm_sys::olm_clear_pk_signing(self.ptr) };
    }
}

impl OlmPkSigning {
    /// Create a new signing object.
    ///
    /// # Arguments
    ///
    /// * `seed` - the seed to use as the private key for signing. The seed must
    ///     have the same length as the seeds generated by
    ///     [`OlmPkSigning::generate_seed()`]. The correct length can be checked
    ///     using [`OlmPkSigning::seed_length()`] as well.
    pub fn new(seed: &[u8]) -> Result<Self, OlmPkSigningError> {
        if seed.len() != OlmPkSigning::seed_length() {
            return Err(OlmPkSigningError::InvalidSeed);
        }

        let mut buffer = ByteBuf::new(unsafe { olm_sys::olm_pk_signing_size() });

        let ptr = unsafe { olm_sys::olm_pk_signing(buffer.as_mut_void_ptr() as *mut _) };
        let pubkey_length = unsafe { olm_sys::olm_pk_signing_public_key_length() };
        let mut pubkey_buffer = vec![0; pubkey_length];

        let ret = unsafe {
            olm_sys::olm_pk_signing_key_from_seed(
                ptr,
                pubkey_buffer.as_mut_ptr() as *mut _,
                pubkey_length,
                seed.as_ptr() as *const _,
                seed.len(),
            )
        };

        if ret == errors::olm_error() {
            Err(OlmPkSigning::last_error(ptr))
        } else {
            Ok(Self {
                ptr,
                _buf: buffer,
                public_key: String::from_utf8(pubkey_buffer)
                    .expect("Can't conver the public key buffer to a string"),
            })
        }
    }

    fn last_error(ptr: *mut olm_sys::OlmPkSigning) -> OlmPkSigningError {
        let error = unsafe {
            let error_raw = olm_sys::olm_pk_signing_last_error(ptr);
            CStr::from_ptr(error_raw).to_str().unwrap()
        };
        error.into()
    }

    /// Get the required seed length.
    pub fn seed_length() -> usize {
        unsafe { olm_sys::olm_pk_signing_seed_length() }
    }

    /// Generate a random seed that can be used to initialize a [`OlmPkSigning`]
    /// object.
    pub fn generate_seed() -> Vec<u8> {
        let length = OlmPkSigning::seed_length();
        let mut buffer = Zeroizing::new(vec![0; length]);

        getrandom(&mut buffer);

        buffer.to_vec()
    }

    /// Get the public key of the the [`OlmPkSigning`] object.
    ///
    /// This can be used to check the signature of a messsage that has been
    /// signed by this object.
    ///
    /// # Example
    ///
    /// ```
    /// # use olm_rs::pk::OlmPkSigning;
    /// # use olm_rs::utility::OlmUtility;
    /// let message = "It's a secret to everyone".to_string();
    ///
    /// let sign = OlmPkSigning::new(&OlmPkSigning::generate_seed()).unwrap();
    /// let utility = OlmUtility::new();
    ///
    /// let signature = sign.sign(&message);
    ///
    /// utility.ed25519_verify(sign.public_key(), &message, signature).unwrap();
    /// ```
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Sign a message using this object.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that should be signed with the private key of
    ///     this object.
    ///
    /// # Panics
    ///
    /// * `OUTPUT_BUFFER_TOO_SMALL` for the signature buffer that is provided to
    /// libolm.
    /// * on malformed UTF-8 coding of the signature provided by libolm.
    pub fn sign(&self, message: &str) -> String {
        let signature_len = unsafe { olm_sys::olm_pk_signature_length() };

        let mut signature = vec![0; signature_len];

        let ret = unsafe {
            olm_sys::olm_pk_sign(
                self.ptr,
                message.as_ptr() as *mut _,
                message.len(),
                signature.as_mut_ptr() as *mut _,
                signature_len,
            )
        };

        if ret == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.ptr));
        }

        String::from_utf8(signature).expect("Can't conver the signature to a string")
    }
}

#[cfg(test)]
mod test {
    use crate::errors::OlmPkDecryptionError;
    use crate::pk::{OlmPkDecryption, OlmPkEncryption, OlmPkSigning, PkMessage};
    use crate::utility::OlmUtility;
    use crate::PicklingMode;

    #[test]
    fn create_pk_sign() {
        assert!(OlmPkSigning::new(&OlmPkSigning::generate_seed()).is_ok());
    }

    #[test]
    fn invalid_seed() {
        assert!(OlmPkSigning::new(&[]).is_err());

        let lo_seed_len = OlmPkSigning::seed_length() - 1;
        let hi_seed_len = OlmPkSigning::seed_length() + 1;

        assert!(OlmPkSigning::new(&vec![0; lo_seed_len]).is_err());
        assert!(OlmPkSigning::new(&vec![0; hi_seed_len]).is_err());
    }

    #[test]
    fn seed_random() {
        let seed_a = OlmPkSigning::generate_seed();
        let seed_b = OlmPkSigning::generate_seed();
        assert_ne!(&seed_a[..], &seed_b[..]);
    }

    #[test]
    fn sign_a_message() {
        let message = "It's a secret to everyone".to_string();
        let sign = OlmPkSigning::new(&OlmPkSigning::generate_seed()).unwrap();
        let utility = OlmUtility::new();

        let signature = sign.sign(&message);
        assert!(utility
            .ed25519_verify(sign.public_key(), &message, signature.clone())
            .is_ok());
        assert!(utility
            .ed25519_verify(sign.public_key(), "Hello world", signature)
            .is_err());
    }

    #[test]
    fn encrypt_a_message() {
        let message = "It's a secret to everyone".to_string();
        let decryption = OlmPkDecryption::new();
        let encryption = OlmPkEncryption::new(decryption.public_key());

        let encrypted_message = encryption.encrypt(&message);

        let plaintext = decryption.decrypt(encrypted_message).unwrap();

        assert_eq!(message, plaintext);
    }

    #[test]
    fn pickle() {
        let message = "It's a secret to everyone".to_string();
        let decryption = OlmPkDecryption::new();
        let encryption = OlmPkEncryption::new(decryption.public_key());

        let encrypted_message = encryption.encrypt(&message);

        let pickle = decryption.pickle(PicklingMode::Unencrypted);
        let decryption = OlmPkDecryption::unpickle(pickle, PicklingMode::Unencrypted).unwrap();

        let plaintext = decryption.decrypt(encrypted_message).unwrap();

        assert_eq!(message, plaintext);
    }

    #[test]
    fn invalid_unpickle() {
        let decryption = OlmPkDecryption::new();

        let pickle = decryption.pickle(PicklingMode::Encrypted {
            key: Vec::from("wordpass"),
        });
        assert!(OlmPkDecryption::unpickle(pickle, PicklingMode::Unencrypted).is_err());
    }

    #[test]
    fn invalid_decrypt() {
        let alice = OlmPkDecryption::new();
        let malory = OlmPkEncryption::new(OlmPkDecryption::new().public_key());

        let encrypted_message = malory.encrypt("It's a secret to everyone");
        assert!(alice.decrypt(encrypted_message).is_err());
    }

    #[test]
    fn attempt_decrypt_invalid_base64() {
        let decryption = OlmPkDecryption::new();
        let message = PkMessage {
            ciphertext: "1".to_string(),
            mac: "".to_string(),
            ephemeral_key: "".to_string(),
        };

        assert_eq!(
            Err(OlmPkDecryptionError::InvalidBase64),
            decryption.decrypt(message)
        );
    }
}
