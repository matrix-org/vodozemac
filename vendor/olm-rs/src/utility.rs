// Copyright 2020 Johannes Hayeß
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

//! This module wraps around all functions following the pattern `olm_utility_*`.

use crate::errors::{self, OlmUtilityError};
use crate::ByteBuf;
use std::ffi::CStr;

pub struct OlmUtility {
    olm_utility_ptr: *mut olm_sys::OlmUtility,
    _olm_utility_buf: ByteBuf,
}

/// Allows you to make use of crytographic hashing via SHA-2 and
/// verifying ed25519 signatures.
impl OlmUtility {
    /// Creates a new instance of OlmUtility.
    ///
    /// # C-API equivalent
    /// `olm_utility`
    ///
    pub fn new() -> Self {
        // allocate the buffer for OlmUtility to be written into
        let mut olm_utility_buf = ByteBuf::new(unsafe { olm_sys::olm_utility_size() });
        let olm_utility_ptr = unsafe { olm_sys::olm_utility(olm_utility_buf.as_mut_void_ptr()) };

        Self {
            olm_utility_ptr,
            _olm_utility_buf: olm_utility_buf,
        }
    }

    /// Returns the last error that occurred for an OlmUtility
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmUtilityError::Unknown is returned on an unknown error code.
    fn last_error(olm_utility_ptr: *mut olm_sys::OlmUtility) -> OlmUtilityError {
        let error_raw = unsafe { olm_sys::olm_utility_last_error(olm_utility_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_MESSAGE_MAC" => OlmUtilityError::BadMessageMac,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmUtilityError::OutputBufferTooSmall,
            "INVALID_BASE64" => OlmUtilityError::InvalidBase64,
            _ => OlmUtilityError::Unknown,
        }
    }

    /// Returns a sha256 of the supplied byte slice.
    ///
    /// # C-API equivalent
    /// `olm_sha256`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied output buffer
    /// * on malformed UTF-8 coding of the hash provided by libolm
    ///
    pub fn sha256_bytes(&self, input_buf: &[u8]) -> String {
        let output_len = unsafe { olm_sys::olm_sha256_length(self.olm_utility_ptr) };
        let mut output_buf = vec![0; output_len];

        let sha256_error = unsafe {
            olm_sys::olm_sha256(
                self.olm_utility_ptr,
                input_buf.as_ptr() as *const _,
                input_buf.len(),
                output_buf.as_mut_ptr() as *mut _,
                output_len,
            )
        };

        // We assume a correct implementation of the SHA256 function here,
        // that always returns a valid UTF-8 string.
        let sha256_result = String::from_utf8(output_buf).unwrap();

        // Errors from sha256 are fatal
        if sha256_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_utility_ptr));
        }

        sha256_result
    }

    /// Convenience function that converts the UTF-8 message
    /// to bytes and then calls [`sha256_bytes()`](Self::sha256_bytes()), returning its output.
    pub fn sha256_utf8_msg(&self, msg: &str) -> String {
        self.sha256_bytes(msg.as_bytes())
    }

    /// Verify a ed25519 signature.
    ///
    /// # Arugments
    /// * `key` - The public part of the ed25519 key that signed the message.
    /// * `message` - The message that was signed.
    /// * `signature` - The signature of the message.
    ///
    /// # C-API equivalent
    /// `olm_ed25519_verify`
    ///
    pub fn ed25519_verify(
        &self,
        key: &str,
        message: &str,
        signature: String,
    ) -> Result<bool, OlmUtilityError> {
        let ed25519_verify_error = unsafe {
            olm_sys::olm_ed25519_verify(
                self.olm_utility_ptr,
                key.as_ptr() as *const _,
                key.len(),
                message.as_ptr() as *const _,
                message.len(),
                signature.as_ptr() as *mut _,
                signature.len(),
            )
        };

        // Since the two values are the same it is safe to copy
        let ed25519_verify_result: usize = ed25519_verify_error;

        if ed25519_verify_error == errors::olm_error() {
            Err(Self::last_error(self.olm_utility_ptr))
        } else {
            Ok(ed25519_verify_result == 0)
        }
    }
}

impl Default for OlmUtility {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmUtility {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_utility(self.olm_utility_ptr);
        }
    }
}
