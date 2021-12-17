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

//! This module wraps around all functions in `outbound_group_session.h`.

use crate::errors;
use crate::errors::OlmGroupSessionError;
use crate::getrandom;
use crate::{ByteBuf, PicklingMode};
use std::ffi::CStr;

use zeroize::Zeroizing;

/// An out-bound group session is responsible for encrypting outgoing
/// communication in a Megolm session.
pub struct OlmOutboundGroupSession {
    group_session_ptr: *mut olm_sys::OlmOutboundGroupSession,
    _group_session_buf: ByteBuf,
}

impl OlmOutboundGroupSession {
    /// Creates a new instance of [`OlmOutboundGroupSession`].
    ///
    /// # C-API equivalent
    /// `olm_init_outbound_group_session`
    ///
    /// # Panics
    /// * `NotEnoughRandom` for creation
    ///
    pub fn new() -> Self {
        let mut olm_outbound_group_session_buf =
            ByteBuf::new(unsafe { olm_sys::olm_outbound_group_session_size() });

        let olm_outbound_group_session_ptr = unsafe {
            olm_sys::olm_outbound_group_session(olm_outbound_group_session_buf.as_mut_void_ptr())
        };

        let random_len = unsafe {
            olm_sys::olm_init_outbound_group_session_random_length(olm_outbound_group_session_ptr)
        };

        let create_error = {
            let mut random_buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; random_len]);
            getrandom(&mut random_buf);

            unsafe {
                olm_sys::olm_init_outbound_group_session(
                    olm_outbound_group_session_ptr,
                    random_buf.as_mut_ptr() as *mut _,
                    random_len,
                )
            }
        };

        if create_error == errors::olm_error() {
            errors::handle_fatal_error(olm_outbound_group_session_ptr);
        }

        OlmOutboundGroupSession {
            group_session_ptr: olm_outbound_group_session_ptr,
            _group_session_buf: olm_outbound_group_session_buf,
        }
    }

    /// Serialises an [`OlmOutboundGroupSession`] to encrypted Base64.
    ///
    /// # C-API equivalent
    /// `olm_pickle_outbound_group_session`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for pickled buffer
    /// * on malformed UTF-8 coding of the pickling provided by libolm
    ///
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let pickled_len =
            unsafe { olm_sys::olm_pickle_outbound_group_session_length(self.group_session_ptr) };
        let mut pickled_buf = vec![0; pickled_len];

        let pickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_pickle_outbound_group_session(
                    self.group_session_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_len,
                )
            }
        };

        let pickled_result = String::from_utf8(pickled_buf).unwrap();

        if pickle_error == errors::olm_error() {
            errors::handle_fatal_error(self.group_session_ptr);
        }

        pickled_result
    }

    /// Deserialises from encrypted Base64 that was previously obtained by pickling an [`OlmOutboundGroupSession`].
    ///
    /// # C-API equivalent
    /// `olm_unpickle_outbound_group_session`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the session was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, mode: PicklingMode) -> Result<Self, OlmGroupSessionError> {
        let pickled_len = pickled.len();
        let pickled_buf = unsafe { pickled.as_bytes_mut() };

        let mut olm_outbound_group_session_buf =
            ByteBuf::new(unsafe { olm_sys::olm_outbound_group_session_size() });

        let olm_outbound_group_session_ptr = unsafe {
            olm_sys::olm_outbound_group_session(olm_outbound_group_session_buf.as_mut_void_ptr())
        };

        let unpickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_unpickle_outbound_group_session(
                    olm_outbound_group_session_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_len,
                )
            }
        };

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_outbound_group_session_ptr))
        } else {
            Ok(OlmOutboundGroupSession {
                group_session_ptr: olm_outbound_group_session_ptr,
                _group_session_buf: olm_outbound_group_session_buf,
            })
        }
    }

    /// Returns the last error that occurred for an [`OlmOutboundGroupSession`].
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmGroupSessionError::Unknown is returned on an unknown error code.
    fn last_error(
        group_session_ptr: *const olm_sys::OlmOutboundGroupSession,
    ) -> OlmGroupSessionError {
        let error_raw =
            unsafe { olm_sys::olm_outbound_group_session_last_error(group_session_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_ACCOUNT_KEY" => OlmGroupSessionError::BadAccountKey,
            "INVALID_BASE64" => OlmGroupSessionError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmGroupSessionError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmGroupSessionError::OutputBufferTooSmall,
            _ => OlmGroupSessionError::Unknown,
        }
    }

    /// Encrypts a plaintext message using the session.
    ///
    /// # C-API equivalent
    /// * `olm_group_encrypt`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for encrypted message
    /// * on malformed UTF-8 coding of the ciphertext provided by libolm
    ///
    pub fn encrypt(&self, plaintext: &str) -> String {
        let plaintext_buf = plaintext.as_bytes();
        let plaintext_len = plaintext_buf.len();
        let plaintext_ptr = plaintext_buf.as_ptr() as *const _;
        let message_max_len = unsafe {
            olm_sys::olm_group_encrypt_message_length(self.group_session_ptr, plaintext_len)
        };
        let mut message_buf: Vec<u8> = vec![0; message_max_len];

        let message_len = unsafe {
            olm_sys::olm_group_encrypt(
                self.group_session_ptr,
                plaintext_ptr,
                plaintext_len,
                message_buf.as_mut_ptr() as *mut _,
                message_max_len,
            )
        };

        let message_result = String::from_utf8(message_buf).unwrap();

        // Can return both final message length or an error code
        let encrypt_error = message_len;
        if encrypt_error == errors::olm_error() {
            errors::handle_fatal_error(self.group_session_ptr);
        }

        message_result
    }

    /// Get the current message index for this session.
    ///
    /// Each message is sent with an increasing index; this returns the index for the next message.
    ///
    /// # C-API equivalent
    /// * `olm_outbound_group_session_message_index`
    ///
    pub fn session_message_index(&self) -> u32 {
        unsafe { olm_sys::olm_outbound_group_session_message_index(self.group_session_ptr) }
    }

    /// Get a base64-encoded identifier for this session.
    ///
    /// # C-API equivalent
    /// * `olm_outbound_group_session_id`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for too small ID buffer
    /// * on malformed UTF-8 coding of the session ID provided by libolm
    ///
    pub fn session_id(&self) -> String {
        let id_max_len =
            unsafe { olm_sys::olm_outbound_group_session_id_length(self.group_session_ptr) };
        let mut id_buf: Vec<u8> = vec![0; id_max_len];

        let id_len = unsafe {
            olm_sys::olm_outbound_group_session_id(
                self.group_session_ptr as *mut _,
                id_buf.as_mut_ptr() as *mut _,
                id_max_len,
            )
        };

        let id_result = String::from_utf8(id_buf).unwrap();

        // Can return both session id length or an error code
        let id_error = id_len;
        if id_error == errors::olm_error() {
            errors::handle_fatal_error(self.group_session_ptr);
        }

        id_result
    }

    /// Get the base64-encoded current ratchet key for this session.
    ///
    /// Each message is sent with a different ratchet key. This function returns the
    /// ratchet key that will be used for the next message.
    ///
    /// # C-API equivalent
    /// * `olm_outbound_group_session_key`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for too small session key buffer
    /// * on malformed UTF-8 coding of the session key provided by libolm
    ///
    pub fn session_key(&self) -> String {
        let key_max_len =
            unsafe { olm_sys::olm_outbound_group_session_key_length(self.group_session_ptr) };
        let mut key_buf: Vec<u8> = vec![0; key_max_len];

        let key_len = unsafe {
            olm_sys::olm_outbound_group_session_key(
                self.group_session_ptr,
                key_buf.as_mut_ptr() as *mut _,
                key_max_len,
            )
        };

        let key_result = String::from_utf8(key_buf).unwrap();

        // Can return both session id length or an error code
        let key_error = key_len;
        if key_error == errors::olm_error() {
            errors::handle_fatal_error(self.group_session_ptr);
        }

        key_result
    }
}

impl Default for OlmOutboundGroupSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmOutboundGroupSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_outbound_group_session(self.group_session_ptr);
        }
    }
}
