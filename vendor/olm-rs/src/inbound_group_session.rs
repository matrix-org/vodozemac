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

//! This module wraps around all functions in `inbound_group_session.h`.

use crate::errors;
use crate::errors::OlmGroupSessionError;
use crate::{ByteBuf, PicklingMode};
use std::ffi::CStr;

use zeroize::Zeroizing;

/// An in-bound group session is responsible for decrypting incoming
/// communication in a Megolm session.
pub struct OlmInboundGroupSession {
    group_session_ptr: *mut olm_sys::OlmInboundGroupSession,
    _group_session_buf: ByteBuf,
}

impl OlmInboundGroupSession {
    /// Creates a new instance of [`OlmInboundGroupSession`].
    ///
    /// # C-API equivalent
    /// `olm_init_inbound_group_session`
    ///
    /// # Errors
    /// * `InvalidBase64` if session key is invalid base64
    /// * `BadSessionKey` if session key is invalid
    ///
    pub fn new(key: &str) -> Result<Self, OlmGroupSessionError> {
        let mut olm_inbound_group_session_buf =
            ByteBuf::new(unsafe { olm_sys::olm_inbound_group_session_size() });

        let olm_inbound_group_session_ptr = unsafe {
            olm_sys::olm_inbound_group_session(olm_inbound_group_session_buf.as_mut_void_ptr())
        };
        let key_buf = key.as_bytes();

        let create_error = unsafe {
            olm_sys::olm_init_inbound_group_session(
                olm_inbound_group_session_ptr as *mut _,
                key_buf.as_ptr(),
                key_buf.len(),
            )
        };

        if create_error == errors::olm_error() {
            Err(Self::last_error(olm_inbound_group_session_ptr))
        } else {
            Ok(OlmInboundGroupSession {
                group_session_ptr: olm_inbound_group_session_ptr,
                _group_session_buf: olm_inbound_group_session_buf,
            })
        }
    }

    /// Import an inbound group session, from a previous export.
    ///
    /// # C-API equivalent
    /// `olm_import_inbound_group_session`
    ///
    /// # Errors
    /// * `InvalidBase64` if session key is invalid base64
    /// * `BadSessionKey` if session key is invalid
    ///
    pub fn import(key: &str) -> Result<Self, OlmGroupSessionError> {
        let mut olm_inbound_group_session_buf =
            ByteBuf::new(unsafe { olm_sys::olm_inbound_group_session_size() });

        let olm_inbound_group_session_ptr = unsafe {
            olm_sys::olm_inbound_group_session(olm_inbound_group_session_buf.as_mut_void_ptr())
        };

        let key_buf = key.as_bytes();
        let key_ptr = key_buf.as_ptr() as *const _;

        let import_error = unsafe {
            olm_sys::olm_import_inbound_group_session(
                olm_inbound_group_session_ptr,
                key_ptr,
                key_buf.len(),
            )
        };

        if import_error == errors::olm_error() {
            Err(Self::last_error(olm_inbound_group_session_ptr))
        } else {
            Ok(OlmInboundGroupSession {
                group_session_ptr: olm_inbound_group_session_ptr,
                _group_session_buf: olm_inbound_group_session_buf,
            })
        }
    }

    /// Serialises an [`OlmInboundGroupSession`] to encrypted Base64.
    ///
    /// # C-API equivalent
    /// `olm_pickle_inbound_group_session`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for `OlmInboundGroupSession`'s pickled buffer
    /// * on malfromed UTF-8 coding of the pickling provided by libolm
    ///
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let mut pickled_buf =
            vec![
                0;
                unsafe { olm_sys::olm_pickle_inbound_group_session_length(self.group_session_ptr) }
            ];

        let pickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_pickle_inbound_group_session(
                    self.group_session_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_buf.len(),
                )
            }
        };

        let pickled_result = String::from_utf8(pickled_buf).unwrap();

        if pickle_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.group_session_ptr));
        }

        pickled_result
    }

    /// Deserialises from encrypted Base64 that was previously obtained by pickling an [`OlmInboundGroupSession`].
    ///
    /// # C-API equivalent
    /// `olm_unpickle_inbound_group_session`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the session was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, mode: PicklingMode) -> Result<Self, OlmGroupSessionError> {
        let pickled_len = pickled.len();
        let pickled_buf = unsafe { pickled.as_bytes_mut() };

        let mut olm_inbound_group_session_buf =
            ByteBuf::new(unsafe { olm_sys::olm_inbound_group_session_size() });

        let olm_inbound_group_session_ptr = unsafe {
            olm_sys::olm_inbound_group_session(olm_inbound_group_session_buf.as_mut_void_ptr())
        };

        let unpickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_unpickle_inbound_group_session(
                    olm_inbound_group_session_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_len,
                )
            }
        };

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_inbound_group_session_ptr))
        } else {
            Ok(OlmInboundGroupSession {
                group_session_ptr: olm_inbound_group_session_ptr,
                _group_session_buf: olm_inbound_group_session_buf,
            })
        }
    }

    /// Returns the last error that occurred for an [`OlmInboundGroupSession`].
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmGroupSessionError::Unknown is returned on an unknown error code.
    fn last_error(
        group_session_ptr: *const olm_sys::OlmInboundGroupSession,
    ) -> OlmGroupSessionError {
        let error_raw = unsafe { olm_sys::olm_inbound_group_session_last_error(group_session_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_ACCOUNT_KEY" => OlmGroupSessionError::BadAccountKey,
            "BAD_MESSAGE_FORMAT" => OlmGroupSessionError::BadMessageFormat,
            "BAD_MESSAGE_MAC" => OlmGroupSessionError::BadMessageMac,
            "BAD_MESSAGE_VERSION" => OlmGroupSessionError::BadMessageVersion,
            "BAD_SESSION_KEY" => OlmGroupSessionError::BadSessionKey,
            "INVALID_BASE64" => OlmGroupSessionError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmGroupSessionError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmGroupSessionError::OutputBufferTooSmall,
            "UNKNOWN_MESSAGE_INDEX" => OlmGroupSessionError::UnknownMessageIndex,
            _ => OlmGroupSessionError::Unknown,
        }
    }

    /// Decrypts ciphertext received for this group session. Decoding is lossy, meaing if
    /// the decrypted plaintext contains invalid UTF-8 symbols, they will
    /// be returned as `U+FFFD` (�).
    ///
    /// Returns both plaintext and message index.
    ///
    /// # C-API equivalent
    /// * `olm_group_decrypt`
    ///
    /// # Errors
    /// * `InvalidBase64` if the message is invalid base64
    /// * `BadMessageVersion` if the message was encrypted with an unsupported version of the protocol
    /// * `BadMessageFormat` if the message headers could not be decoded
    /// * `BadMessageMac` if the message could not be verified
    /// * `UnknownMessageIndex` if we do not have a session key corresponding to the message's index
    /// (ie, it was sent before the session key was shared with us)
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for decrypted ciphertext
    ///
    pub fn decrypt(&self, mut message: String) -> Result<(String, u32), OlmGroupSessionError> {
        // This is for capturing the output of olm_group_decrypt
        let message_index = 0;

        // We need to clone the message because
        // olm_decrypt_max_plaintext_length destroys the input buffer
        let mut message_for_len = message.clone();
        let message_buf = unsafe { message_for_len.as_bytes_mut() };
        let message_len = message_buf.len();
        let message_ptr = message_buf.as_mut_ptr() as *mut _;

        let max_plaintext_length = {
            let ret = unsafe {
                olm_sys::olm_group_decrypt_max_plaintext_length(
                    self.group_session_ptr,
                    message_ptr,
                    message_len,
                )
            };

            if ret == errors::olm_error() {
                return Err(OlmGroupSessionError::InvalidBase64);
            }

            ret
        };

        let mut plaintext_buf = Zeroizing::new(vec![0; max_plaintext_length]);
        let message_buf = unsafe { message.as_bytes_mut() };
        let message_len = message_buf.len();
        let message_ptr = message_buf.as_mut_ptr() as *mut _;
        let plaintext_max_len = plaintext_buf.len();

        let plaintext_len = unsafe {
            olm_sys::olm_group_decrypt(
                self.group_session_ptr,
                message_ptr,
                message_len,
                plaintext_buf.as_mut_ptr() as *mut _,
                plaintext_max_len,
                message_index as *mut _,
            )
        };

        // Error code or plaintext length is returned
        let decrypt_error = plaintext_len;

        if decrypt_error == errors::olm_error() {
            let error_code = Self::last_error(self.group_session_ptr);

            if error_code == OlmGroupSessionError::OutputBufferTooSmall {
                errors::handle_fatal_error(OlmGroupSessionError::OutputBufferTooSmall);
            }

            return Err(error_code);
        }

        plaintext_buf.truncate(plaintext_len);
        Ok((
            String::from_utf8_lossy(&plaintext_buf).to_string(),
            message_index,
        ))
    }

    /// Export the base64-encoded ratchet key for this session, at the given index,
    /// in a format which can be used by import
    ///
    /// # C-API equivalent
    /// * `olm_export_inbound_group_session`
    ///
    /// # Errors
    /// * `UnkownMessageIndex` if we do not have a session key corresponding to the given index
    /// (ie, it was sent before the session key was shared with us)
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for export buffer
    /// * on malformed UTF-8 coding of the exported session provided by libolm
    ///
    pub fn export(&self, message_index: u32) -> Result<String, OlmGroupSessionError> {
        let key_len =
            unsafe { olm_sys::olm_export_inbound_group_session_length(self.group_session_ptr) };
        let mut key_buf: Vec<u8> = vec![0; key_len];

        let export_error = unsafe {
            olm_sys::olm_export_inbound_group_session(
                self.group_session_ptr,
                key_buf.as_mut_ptr() as *mut _,
                key_len,
                message_index,
            )
        };

        let export_result = String::from_utf8(key_buf).unwrap();

        if export_error == errors::olm_error() {
            let error_code = Self::last_error(self.group_session_ptr);
            if error_code == OlmGroupSessionError::OutputBufferTooSmall {
                errors::handle_fatal_error(OlmGroupSessionError::OutputBufferTooSmall);
            }

            Err(error_code)
        } else {
            Ok(export_result)
        }
    }

    /// Get the first message index we know how to decrypt.
    ///
    /// # C-API equivalent
    /// * `olm_inbound_group_session_first_known_index`
    ///
    pub fn first_known_index(&self) -> u32 {
        unsafe { olm_sys::olm_inbound_group_session_first_known_index(self.group_session_ptr) }
    }

    /// Get a base64-encoded identifier for this session.
    ///
    /// # C-API equivalent
    /// * `olm_inbound_group_session_id`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for session ID buffer
    /// * on malformed UTF-8 coding of the session ID provided by libolm
    ///
    pub fn session_id(&self) -> String {
        let session_id_len =
            unsafe { olm_sys::olm_inbound_group_session_id_length(self.group_session_ptr) };
        let mut session_id_buf: Vec<u8> = vec![0; session_id_len];

        let session_id_error = unsafe {
            olm_sys::olm_inbound_group_session_id(
                self.group_session_ptr,
                session_id_buf.as_mut_ptr() as *mut _,
                session_id_len,
            )
        };

        let session_id_result = String::from_utf8(session_id_buf).unwrap();

        if session_id_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.group_session_ptr));
        }

        session_id_result
    }

    /// Check if the session has been verified as a valid session.
    ///
    /// (A session is verified either because the original session share was signed,
    /// or because we have subsequently successfully decrypted a message.)
    ///
    /// This is mainly intended for the unit tests (in libolm), currently.
    ///
    /// # C-API equivalent
    /// * `olm_inbound_group_session_is_verified`
    pub fn session_is_verified(&self) -> bool {
        // To get the bool value of an int_c type, check for inequality with zero.
        //
        // Truth table:
        // +-----------+----------+------+
        // |Orig. value|Expression|Result|
        // +-----------+----------+------+
        // |0          |0 != 0    |false |
        // +-----------+----------+------+
        // |1          |0 != 1    |true  |
        // +-----------+----------+------+

        0 != unsafe { olm_sys::olm_inbound_group_session_is_verified(self.group_session_ptr) }
    }
}

impl Drop for OlmInboundGroupSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_inbound_group_session(self.group_session_ptr);
        }
    }
}
