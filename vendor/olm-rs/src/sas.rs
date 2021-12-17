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

//! This module wraps around all functions following the pattern `olm_sas_*`.
//!
//! # Example
//!
//! ```
//! # use olm_rs::sas::OlmSas;
//! let mut alice = OlmSas::new();
//! let mut bob = OlmSas::new();
//!
//! alice.set_their_public_key(bob.public_key()).unwrap();
//! bob.set_their_public_key(alice.public_key()).unwrap();
//!
//! assert_eq!(
//!     alice.generate_bytes("", 5).unwrap(),
//!     bob.generate_bytes("", 5).unwrap()
//! );
//!
//! ```

use std::ffi::CStr;

use zeroize::Zeroizing;

use crate::errors::{self, OlmSasError};
use crate::getrandom;
use crate::ByteBuf;

pub struct OlmSas {
    sas_ptr: *mut olm_sys::OlmSAS,
    _sas_buf: ByteBuf,
    public_key_set: bool,
}

impl Drop for OlmSas {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_sas(self.sas_ptr);
        }
    }
}

impl Default for OlmSas {
    fn default() -> Self {
        Self::new()
    }
}

impl OlmSas {
    pub fn new() -> Self {
        // allocate buffer for OlmAccount to be written into
        let mut sas_buf = ByteBuf::new(unsafe { olm_sys::olm_sas_size() });
        let ptr = unsafe { olm_sys::olm_sas(sas_buf.as_mut_void_ptr()) };

        let random_len = unsafe { olm_sys::olm_create_sas_random_length(ptr) };
        let mut random_buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; random_len]);
        getrandom(&mut random_buf);

        let ret =
            unsafe { olm_sys::olm_create_sas(ptr, random_buf.as_mut_ptr() as *mut _, random_len) };

        if ret == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(ptr));
        }

        Self {
            sas_ptr: ptr,
            _sas_buf: sas_buf,
            public_key_set: false,
        }
    }

    /// Get the public key for the SAS object.
    ///
    /// This returns the public key of the SAS object that can then be shared
    /// with another user to perform the authentication process.
    pub fn public_key(&self) -> String {
        let pubkey_length = unsafe { olm_sys::olm_sas_pubkey_length(self.sas_ptr) };

        let mut buffer: Vec<u8> = vec![0; pubkey_length];

        let ret = unsafe {
            olm_sys::olm_sas_get_pubkey(self.sas_ptr, buffer.as_mut_ptr() as *mut _, pubkey_length)
        };

        if ret == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.sas_ptr));
        }

        unsafe { String::from_utf8_unchecked(buffer) }
    }

    /// Returns the last error that occurred for an OlmSas object.
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmSasError::Unknown is returned on an unknown error code.
    fn last_error(sas_ptr: *mut olm_sys::OlmSAS) -> OlmSasError {
        let error = unsafe {
            let error_raw = olm_sys::olm_sas_last_error(sas_ptr);
            CStr::from_ptr(error_raw).to_str().unwrap()
        };

        match error {
            "NOT_ENOUGH_RANDOM" => OlmSasError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmSasError::OutputBufferTooSmall,
            "INPUT_BUFFER_TOO_SMALL" => OlmSasError::OutputBufferTooSmall,
            _ => OlmSasError::Unknown,
        }
    }

    /// Set the public key of the other user.
    ///
    /// This sets the public key of the other user, it needs to be set before
    /// bytes can be generated for the authentication string and a MAC can be
    /// calculated.
    ///
    /// Returns an error if the public key was too short or invalid.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the other user.
    pub fn set_their_public_key(&mut self, public_key: String) -> Result<(), OlmSasError> {
        let ret = unsafe {
            olm_sys::olm_sas_set_their_key(
                self.sas_ptr,
                public_key.as_ptr() as *mut _,
                public_key.len(),
            )
        };

        if ret == errors::olm_error() {
            Err(Self::last_error(self.sas_ptr))
        } else {
            self.public_key_set = true;
            Ok(())
        }
    }

    /// Generate bytes to use for the short authentication string.
    ///
    /// Note the other public key needs to be set for this method to work.
    /// Returns an error if it isn't set.
    ///
    /// # Arguments
    ///
    /// * `extra_info` - Extra information to mix in when generating the
    ///     bytes.
    ///
    /// * `length` - The number of bytes to generate.
    pub fn generate_bytes(&self, extra_info: &str, length: usize) -> Result<Vec<u8>, OlmSasError> {
        if !self.public_key_set {
            return Err(OlmSasError::OtherPublicKeyUnset);
        } else if length < 1 {
            return Err(OlmSasError::InvalidLength);
        }

        let mut out_buffer = vec![0; length];

        let ret = unsafe {
            olm_sys::olm_sas_generate_bytes(
                self.sas_ptr,
                extra_info.as_ptr() as *mut _,
                extra_info.len(),
                out_buffer.as_mut_ptr() as *mut _,
                length,
            )
        };

        if ret == errors::olm_error() {
            Err(Self::last_error(self.sas_ptr))
        } else {
            Ok(out_buffer)
        }
    }

    /// Generate a message authentication code based on the shared secret.
    ///
    /// Note the other public key needs to be set for this method to work.
    /// Returns an error if it isn't set.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to produce the authentication code for.
    ///
    /// * `extra_info` - Extra information to mix in when generating the MAC.
    pub fn calculate_mac(&self, message: &str, extra_info: &str) -> Result<String, OlmSasError> {
        if !self.public_key_set {
            return Err(OlmSasError::OtherPublicKeyUnset);
        }

        let mac_length = unsafe { olm_sys::olm_sas_mac_length(self.sas_ptr) };
        let mut mac_buffer = vec![0; mac_length];

        let ret = unsafe {
            olm_sys::olm_sas_calculate_mac(
                self.sas_ptr,
                message.as_ptr() as *mut _,
                message.len(),
                extra_info.as_ptr() as *mut _,
                extra_info.len(),
                mac_buffer.as_mut_ptr() as *mut _,
                mac_length,
            )
        };

        if ret == errors::olm_error() {
            Err(Self::last_error(self.sas_ptr))
        } else {
            Ok(unsafe { String::from_utf8_unchecked(mac_buffer) })
        }
    }

    /// Generate a message authentication code based on the shared secret, producing base64 strings
    /// compatible with other base64 implementations.
    ///
    /// Note the other public key needs to be set for this method to work.
    /// Returns an error if it isn't set.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to produce the authentication code for.
    ///
    /// * `extra_info` - Extra information to mix in when generating the MAC.
    pub fn calculate_mac_fixed_base64(&self, message: &str, extra_info: &str) -> Result<String, OlmSasError> {
        if !self.public_key_set {
            return Err(OlmSasError::OtherPublicKeyUnset);
        }

        let mac_length = unsafe { olm_sys::olm_sas_mac_length(self.sas_ptr) };
        let mut mac_buffer = vec![0; mac_length];

        let ret = unsafe {
            olm_sys::olm_sas_calculate_mac_fixed_base64(
                self.sas_ptr,
                message.as_ptr() as *mut _,
                message.len(),
                extra_info.as_ptr() as *mut _,
                extra_info.len(),
                mac_buffer.as_mut_ptr() as *mut _,
                mac_length,
            )
        };

        if ret == errors::olm_error() {
            Err(Self::last_error(self.sas_ptr))
        } else {
            Ok(unsafe { String::from_utf8_unchecked(mac_buffer) })
        }
    }
}

#[cfg(test)]
mod test {
    use crate::sas::OlmSas;

    #[test]
    fn test_creation() {
        let alice = OlmSas::new();
        assert!(!alice.public_key().is_empty());
    }

    #[test]
    fn test_set_pubkey() {
        let mut alice = OlmSas::new();

        assert!(alice.set_their_public_key(alice.public_key()).is_ok());
        assert!(alice.set_their_public_key("".to_string()).is_err());
    }

    #[test]
    fn test_generate_bytes() {
        let mut alice = OlmSas::new();
        let mut bob = OlmSas::new();

        assert!(alice.generate_bytes("", 5).is_err());

        assert!(alice.set_their_public_key(bob.public_key()).is_ok());
        assert!(bob.set_their_public_key(alice.public_key()).is_ok());

        assert_eq!(
            alice.generate_bytes("", 5).unwrap(),
            bob.generate_bytes("", 5).unwrap()
        );
        assert_ne!(
            alice.generate_bytes("fake", 5).unwrap(),
            bob.generate_bytes("", 5).unwrap()
        );
    }

    #[test]
    fn test_calculate_mac() {
        let mut alice = OlmSas::new();
        let mut bob = OlmSas::new();

        let message = "It's a secret to everyone".to_string();

        assert!(alice.calculate_mac(&message, "").is_err());

        assert!(alice.set_their_public_key(bob.public_key()).is_ok());
        assert!(bob.set_their_public_key(alice.public_key()).is_ok());

        assert_eq!(
            alice.calculate_mac(&message, "").unwrap(),
            bob.calculate_mac(&message, "").unwrap()
        );
        assert_ne!(
            alice.calculate_mac("fake", "").unwrap(),
            bob.calculate_mac(&message, "").unwrap()
        );
    }
}
