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

//! This module wraps around all functions following the pattern `olm_account_*`.

use crate::errors::{self, OlmAccountError, OlmSessionError};
use crate::getrandom;
use crate::session::{OlmSession, PreKeyMessage};
use crate::{ByteBuf, PicklingMode};

#[cfg(feature = "deserialization")]
use std::collections::{hash_map::Iter, hash_map::Keys, hash_map::Values, HashMap};
use std::ffi::CStr;

#[cfg(feature = "deserialization")]
use serde::Deserialize;
#[cfg(feature = "deserialization")]
use serde_json::Value;
use zeroize::Zeroizing;

/// An olm account manages all cryptographic keys used on a device.
/// ```
/// use olm_rs::account::OlmAccount;
///
/// let olm_account = OlmAccount::new();
/// println!("{:?}", olm_account.identity_keys());
/// ```
pub struct OlmAccount {
    /// Pointer by which libolm acquires the data saved in an instance of OlmAccount
    pub(crate) olm_account_ptr: *mut olm_sys::OlmAccount,
    _olm_account_buf: ByteBuf,
}

#[cfg(feature = "deserialization")]
/// Struct representing the parsed result of [`OlmAccount::identity_keys()`].
#[derive(Deserialize, Debug, PartialEq)]
pub struct IdentityKeys {
    #[serde(flatten)]
    keys: HashMap<String, String>,
}

#[cfg(feature = "deserialization")]
impl IdentityKeys {
    /// Get the public part of the ed25519 key of the account.
    pub fn ed25519(&self) -> &str {
        &self.keys["ed25519"]
    }

    /// Get the public part of the curve25519 key of the account.
    pub fn curve25519(&self) -> &str {
        &self.keys["curve25519"]
    }

    /// Get a reference to the key of the given key type.
    pub fn get(&self, key_type: &str) -> Option<&str> {
        let ret = self.keys.get(key_type);
        ret.map(|x| &**x)
    }

    /// An iterator visiting all public keys of the account.
    pub fn values(&self) -> Values<String, String> {
        self.keys.values()
    }

    /// An iterator visiting all key types of the account.
    pub fn keys(&self) -> Keys<String, String> {
        self.keys.keys()
    }

    /// An iterator visiting all key-type, key pairs of the account.
    pub fn iter(&self) -> Iter<String, String> {
        self.keys.iter()
    }

    /// Returns true if the account contains a key with the given key type.
    pub fn contains_key(&self, key_type: &str) -> bool {
        self.keys.contains_key(key_type)
    }
}

#[cfg(feature = "deserialization")]
/// Struct representing the parsed result of [`OlmAccount::fallback_key()`].
#[derive(Deserialize, Debug, PartialEq)]
pub struct FallbackKey {
    index: String,
    key: String,
}

#[cfg(feature = "deserialization")]
impl FallbackKey {
    /// Get the public part of this fallback key.
    pub fn curve25519(&self) -> &str {
        &self.key
    }

    /// Get the index associated with this fallback key.
    pub fn index(&self) -> &str {
        &self.index
    }
}

#[cfg(feature = "deserialization")]
#[derive(Deserialize, Debug, PartialEq)]
/// Struct representing the the one-time keys.
/// The keys can be accessed in a map-like fashion.
pub struct OneTimeKeys {
    #[serde(flatten)]
    keys: HashMap<String, HashMap<String, String>>,
}

#[cfg(feature = "deserialization")]
impl OneTimeKeys {
    /// Get the HashMap containing the curve25519 one-time keys.
    /// This is the same as using `get("curve25519").unwrap()`
    pub fn curve25519(&self) -> &HashMap<String, String> {
        &self.keys["curve25519"]
    }

    /// Get a reference to the hashmap corresponding to given key type.
    pub fn get(&self, key_type: &str) -> Option<&HashMap<String, String>> {
        self.keys.get(key_type)
    }

    /// An iterator visiting all one-time key hashmaps in an arbitrary order.
    pub fn values(&self) -> Values<String, HashMap<String, String>> {
        self.keys.values()
    }

    /// An iterator visiting all one-time key types in an arbitrary order.
    pub fn keys(&self) -> Keys<String, HashMap<String, String>> {
        self.keys.keys()
    }

    /// An iterator visiting all one-time key types and their respective
    /// key hashmaps in an arbitrary order.
    pub fn iter(&self) -> Iter<String, HashMap<String, String>> {
        self.keys.iter()
    }

    /// Returns `true` if the struct contains the given key type.
    /// This does not mean that there are any keys for the given key type.
    pub fn contains_key(&self, key_type: &str) -> bool {
        self.keys.contains_key(key_type)
    }
}

impl OlmAccount {
    /// Creates a new instance of OlmAccount. During the instantiation the Ed25519 fingerprint key pair
    /// and the Curve25519 identity key pair are generated. For more information see
    /// [here](https://matrix.org/docs/guides/e2e_implementation.html#keys-used-in-end-to-end-encryption).
    ///
    /// # C-API equivalent
    /// `olm_create_account`
    ///
    /// # Panics
    /// * `NOT_ENOUGH_RANDOM` for OlmAccount's creation
    ///
    pub fn new() -> Self {
        // allocate buffer for OlmAccount to be written into
        let mut olm_account_buf = ByteBuf::new(unsafe { olm_sys::olm_account_size() });

        // let libolm populate the allocated memory
        let olm_account_ptr = unsafe { olm_sys::olm_account(olm_account_buf.as_mut_void_ptr()) };

        let create_error = {
            // determine optimal length of the random buffer
            let random_len = unsafe { olm_sys::olm_create_account_random_length(olm_account_ptr) };
            let mut random_buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; random_len]);
            getrandom(&mut random_buf);

            // create OlmAccount with supplied random data
            unsafe {
                olm_sys::olm_create_account(
                    olm_account_ptr,
                    random_buf.as_mut_ptr() as *mut _,
                    random_len,
                )
            }
        };

        if create_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(olm_account_ptr));
        }
        OlmAccount {
            olm_account_ptr,
            _olm_account_buf: olm_account_buf,
        }
    }

    /// Serialises an [`OlmAccount`] to encrypted Base64.
    ///
    /// # C-API equivalent
    /// `olm_pickle_account`
    ///
    /// # Example
    /// ```
    /// use olm_rs::account::OlmAccount;
    /// use olm_rs::PicklingMode;
    ///
    /// let identity_keys;
    /// let olm_account = OlmAccount::new();
    /// identity_keys = olm_account.identity_keys();
    /// let pickled = olm_account.pickle(PicklingMode::Unencrypted);
    /// let olm_account_2 = OlmAccount::unpickle(pickled, PicklingMode::Unencrypted).unwrap();
    /// let identity_keys_2 = olm_account_2.identity_keys();
    ///
    /// assert_eq!(identity_keys, identity_keys_2);
    /// ```
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for OlmAccount's pickled buffer
    /// * on malformed UTF-8 coding for pickling provided by libolm
    ///
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let mut pickled_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_pickle_account_length(self.olm_account_ptr) }];

        let pickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_pickle_account(
                    self.olm_account_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_buf.len(),
                )
            }
        };

        let pickled_result = String::from_utf8(pickled_buf).unwrap();

        if pickle_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        pickled_result
    }

    /// Deserialises from encrypted Base64 that was previously obtained by pickling an [`OlmAccount`].
    ///
    /// # C-API equivalent
    /// `olm_unpickle_account`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the account was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, mode: PicklingMode) -> Result<Self, OlmAccountError> {
        let pickled_len = pickled.len();
        let pickled_buf = Box::new(unsafe { pickled.as_bytes_mut() });

        let mut olm_account_buf = ByteBuf::new(unsafe { olm_sys::olm_account_size() });
        let olm_account_ptr = unsafe { olm_sys::olm_account(olm_account_buf.as_mut_void_ptr()) };

        let unpickle_error = {
            let key = Zeroizing::new(crate::convert_pickling_mode_to_key(mode));

            unsafe {
                olm_sys::olm_unpickle_account(
                    olm_account_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_len,
                )
            }
        };

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_account_ptr))
        } else {
            Ok(OlmAccount {
                olm_account_ptr,
                _olm_account_buf: olm_account_buf,
            })
        }
    }

    /// Returns the account's public identity keys already formatted as JSON and BASE64.
    ///
    /// # C-API equivalent
    /// `olm_account_identity_keys`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied identity keys buffer
    /// * on malformed UTF-8 coding of the identity keys provided by libolm
    ///
    pub fn identity_keys(&self) -> String {
        // get buffer length of identity keys
        let keys_len = unsafe { olm_sys::olm_account_identity_keys_length(self.olm_account_ptr) };
        let mut identity_keys_buf: Vec<u8> = vec![0; keys_len];

        // write keys data in the keys buffer
        let identity_keys_error = unsafe {
            olm_sys::olm_account_identity_keys(
                self.olm_account_ptr,
                identity_keys_buf.as_mut_ptr() as *mut _,
                keys_len,
            )
        };

        // String is constructed from the keys buffer and memory is freed after exiting the scope.
        // No memory should be leaked.
        let identity_keys_result = String::from_utf8(identity_keys_buf).unwrap();

        if identity_keys_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        identity_keys_result
    }

    /// Returns the account's public identity keys.
    #[cfg(feature = "deserialization")]
    pub fn parsed_identity_keys(&self) -> IdentityKeys {
        serde_json::from_str(&self.identity_keys()).expect("Can't deserialize identity keys")
    }

    /// Returns the last error that occurred for an OlmAccount.
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmAccountError::Unknown is returned on an unknown error code.
    fn last_error(olm_account_ptr: *mut olm_sys::OlmAccount) -> OlmAccountError {
        let error;
        // get CString error code and convert to String
        unsafe {
            let error_raw = olm_sys::olm_account_last_error(olm_account_ptr);
            error = CStr::from_ptr(error_raw).to_str().unwrap();
        }

        match error {
            "BAD_ACCOUNT_KEY" => OlmAccountError::BadAccountKey,
            "BAD_MESSAGE_KEY_ID" => OlmAccountError::BadMessageKeyId,
            "INVALID_BASE64" => OlmAccountError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmAccountError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmAccountError::OutputBufferTooSmall,
            _ => OlmAccountError::Unknown,
        }
    }

    /// Returns the signature of the supplied byte slice.
    ///
    /// # C-API equivalent
    /// `olm_account_sign`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied signature buffer
    /// * on malformed UTF-8 coding of the signature provided by libolm
    ///
    pub fn sign(&self, message: &str) -> String {
        let message_buf = message.as_bytes();
        let message_ptr = message_buf.as_ptr() as *const _;

        let signature_len = unsafe { olm_sys::olm_account_signature_length(self.olm_account_ptr) };
        let mut signature_buf: Vec<u8> = vec![0; signature_len];

        let signature_error = unsafe {
            olm_sys::olm_account_sign(
                self.olm_account_ptr,
                message_ptr,
                message_buf.len(),
                signature_buf.as_mut_ptr() as *mut _,
                signature_len,
            )
        };

        let signature_result = String::from_utf8(signature_buf).unwrap();

        if signature_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        signature_result
    }

    /// Maximum number of one time keys that this OlmAccount can currently hold.
    ///
    /// # C-API equivalent
    /// `olm_account_max_number_of_one_time_keys`
    ///
    pub fn max_number_of_one_time_keys(&self) -> usize {
        unsafe { olm_sys::olm_account_max_number_of_one_time_keys(self.olm_account_ptr) }
    }

    /// Generates the supplied number of one time keys.
    ///
    /// # C-API equivalent
    /// `olm_account_generate_one_time_keys`
    ///
    /// # Panics
    /// * `NOT_ENOUGH_RANDOM` for the creation of one time keys
    ///
    pub fn generate_one_time_keys(&self, number_of_keys: usize) {
        // Get correct length for the random buffer
        let random_len = unsafe {
            olm_sys::olm_account_generate_one_time_keys_random_length(
                self.olm_account_ptr,
                number_of_keys,
            )
        };

        let generate_error = {
            // Construct and populate random buffer
            let mut random_buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; random_len]);
            getrandom(&mut random_buf);

            // Call function for generating one time keys
            unsafe {
                olm_sys::olm_account_generate_one_time_keys(
                    self.olm_account_ptr,
                    number_of_keys,
                    random_buf.as_mut_ptr() as *mut _,
                    random_len,
                )
            }
        };

        if generate_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }
    }

    /// Gets the OlmAccount's one time keys formatted as JSON.
    ///
    /// # C-API equivalent
    /// `olm_account_one_time_keys`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied one time keys buffer
    /// * on malformed UTF-8 coding of the keys provided by libolm
    ///
    pub fn one_time_keys(&self) -> String {
        // get buffer length of OTKs
        let otks_len = unsafe { olm_sys::olm_account_one_time_keys_length(self.olm_account_ptr) };
        let mut otks_buf: Vec<u8> = vec![0; otks_len];

        // write OTKs data in the OTKs buffer
        let otks_error = unsafe {
            olm_sys::olm_account_one_time_keys(
                self.olm_account_ptr,
                otks_buf.as_mut_ptr() as *mut _,
                otks_len,
            )
        };

        // String is constructed from the OTKs buffer and memory is freed after exiting the scope.
        let otks_result = String::from_utf8(otks_buf).unwrap();

        if otks_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        otks_result
    }

    #[cfg(feature = "deserialization")]
    /// Returns the account's one-time keys.
    pub fn parsed_one_time_keys(&self) -> OneTimeKeys {
        serde_json::from_str(&self.one_time_keys()).expect("Can't deserialize one-time keys.")
    }

    /// Mark the current set of one time keys as published.
    ///
    /// # C-API equivalent
    /// `olm_account_mark_keys_as_published`
    ///
    pub fn mark_keys_as_published(&self) {
        unsafe {
            olm_sys::olm_account_mark_keys_as_published(self.olm_account_ptr);
        }
    }

    /// Remove the one time key used to create the supplied session.
    ///
    /// # C-API equivalent
    /// `olm_remove_one_time_keys`
    ///
    /// # Errors
    /// * `BAD_MESSAGE_KEY_ID` when the account doesn't hold a matching one time key
    ///
    pub fn remove_one_time_keys(&self, session: &OlmSession) -> Result<(), OlmAccountError> {
        let remove_error = unsafe {
            olm_sys::olm_remove_one_time_keys(self.olm_account_ptr, session.olm_session_ptr)
        };

        if remove_error == errors::olm_error() {
            Err(Self::last_error(self.olm_account_ptr))
        } else {
            Ok(())
        }
    }

    /// Generates a new fallback key. Only one previous fallback key is stored.
    ///
    /// # C-API equivalent
    /// `olm_account_generate_fallback_key`
    ///
    /// # Panics
    /// * `NOT_ENOUGH_RANDOM`
    ///
    pub fn generate_fallback_key(&self) {
        // determine optimal length of the random buffer
        let random_len = unsafe {
            olm_sys::olm_account_generate_fallback_key_random_length(self.olm_account_ptr)
        };
        let mut random_buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; random_len]);
        getrandom(&mut random_buf);

        // write keys data in the keys buffer
        let fallback_key_error = unsafe {
            olm_sys::olm_account_generate_fallback_key(
                self.olm_account_ptr,
                random_buf.as_mut_ptr() as *mut _,
                random_len,
            )
        };

        if fallback_key_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }
    }

    /// Output fallback key of this account in JSON format.
    ///
    /// This is what the output looks like before generating an
    /// initial fallback key:
    /// ```json
    /// {
    ///     "curve25519": {}
    /// }
    /// ```
    ///
    /// And after:
    /// ```json
    /// {
    ///     "curve25519": {
    ///         "AAAAAQ": "u4XQpRre6j7peD4clRq9d56kRbwnVEAsavIiZHHZekY"
    ///     }
    /// }
    /// ```
    ///
    /// # C-API equivalent
    /// `olm_account_one_time_key`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL`
    ///
    pub fn fallback_key(&self) -> String {
        // get buffer length of fallback keys
        let fallback_len =
            unsafe { olm_sys::olm_account_unpublished_fallback_key_length(self.olm_account_ptr) };
        let mut fallback_buf: Vec<u8> = vec![0; fallback_len];

        // write fallbacks key data in the fallback key buffer
        let fallback_error = unsafe {
            olm_sys::olm_account_unpublished_fallback_key(
                self.olm_account_ptr,
                fallback_buf.as_mut_ptr() as *mut _,
                fallback_len,
            )
        };

        if fallback_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        // String is constructed from the fallback key buffer and memory is freed after exiting the scope.
        String::from_utf8(fallback_buf).unwrap()
    }

    #[cfg(feature = "deserialization")]
    /// Returns the account's fallback key. `None` if no fallback key has been generated yet.
    pub fn parsed_fallback_key(&self) -> Option<FallbackKey> {
        let parsed_fallback: Value =
            serde_json::from_str(&self.fallback_key()).expect("Fallback key isn't in JSON format.");

        // We make some assumptions about the structure of the parsed JSON.
        // 1) At the top level is the index "curve25519" that contains an object
        // 2) This object is either empty or contains a singular entry to a (key) string
        parsed_fallback["curve25519"]
            .as_object()
            .unwrap()
            .iter()
            .next()
            .map(|(index, key_value)| FallbackKey {
                index: index.clone(),
                key: key_value.as_str().unwrap().to_string(),
            })
    }

    /// Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    ///
    /// # Arguments
    ///
    /// * `message` - An Olm pre-key message that was encrypted for this
    /// account.
    ///
    /// # Errors
    /// * `InvalidBase64`
    /// * `BadMessageVersion`
    /// * `BadMessageFormat`
    /// * `BadMessageKeyId`
    ///
    pub fn create_inbound_session(
        &self,
        message: PreKeyMessage,
    ) -> Result<OlmSession, OlmSessionError> {
        OlmSession::create_inbound_session(self, message)
    }

    /// Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    ///
    /// * `their_identity_key` - The identity key of an Olm account that
    /// encrypted this Olm message.
    ///
    /// * `message` - An Olm pre-key message that was encrypted for this
    /// account.
    ///
    /// # Errors
    /// * `InvalidBase64`
    /// * `BadMessageVersion`
    /// * `BadMessageFormat`
    /// * `BadMessageKeyId`
    ///
    pub fn create_inbound_session_from(
        &self,
        their_identity_key: &str,
        message: PreKeyMessage,
    ) -> Result<OlmSession, OlmSessionError> {
        OlmSession::create_inbound_session_from(self, their_identity_key, message)
    }

    /// Creates an outbound session for sending messages to a specific
    /// identity and one time key.
    ///
    /// # Errors
    /// * `InvalidBase64` for invalid base64 coding on supplied arguments
    ///
    /// # Panics
    /// * `NotEnoughRandom` if not enough random data was supplied
    ///
    pub fn create_outbound_session(
        &self,
        their_identity_key: &str,
        their_one_time_key: &str,
    ) -> Result<OlmSession, OlmSessionError> {
        OlmSession::create_outbound_session(self, their_identity_key, their_one_time_key)
    }
}

impl Default for OlmAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmAccount {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_account(self.olm_account_ptr);
        }
    }
}

#[cfg(test)]
mod test {
    use super::OlmAccount;
    use serde_json::Value;

    #[test]
    fn fallback_key() {
        let account = OlmAccount::new();

        assert!(account.parsed_fallback_key().is_none());

        account.generate_fallback_key();

        let parsed_fallback = account.parsed_fallback_key().unwrap();
        let manually_parsed_fallback: Value = serde_json::from_str(&account.fallback_key())
            .expect("Fallback key isn't in JSON format.");
        assert_eq!(
            parsed_fallback.curve25519(),
            manually_parsed_fallback["curve25519"][parsed_fallback.index()]
        );
    }

    #[cfg(feature = "deserialization")]
    #[test]
    fn parsed_keys() {
        let account = OlmAccount::new();
        let identity_keys = json::parse(&account.identity_keys()).unwrap();
        let identity_keys_parsed = account.parsed_identity_keys();
        assert_eq!(
            identity_keys_parsed.curve25519(),
            identity_keys["curve25519"]
        );
        assert_eq!(identity_keys_parsed.ed25519(), identity_keys["ed25519"]);
    }
}
