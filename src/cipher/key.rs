// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use aes::{
    cipher::{generic_array::GenericArray, IvSizeUser, KeySizeUser},
    Aes256,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Aes256CbcEnc;

type Aes256Key = GenericArray<u8, <Aes256 as KeySizeUser>::KeySize>;
type Aes256Iv = GenericArray<u8, <Aes256CbcEnc as IvSizeUser>::IvSize>;
type HmacSha256Key = [u8; 32];

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ExpandedKeys(Box<[u8; 80]>);

impl ExpandedKeys {
    const OLM_HKDF_INFO: &'static [u8] = b"OLM_KEYS";
    const MEGOLM_HKDF_INFO: &'static [u8] = b"MEGOLM_KEYS";

    fn new(message_key: &[u8; 32]) -> Self {
        Self::new_helper(message_key, Self::OLM_HKDF_INFO)
    }

    fn new_megolm(message_key: &[u8; 128]) -> Self {
        Self::new_helper(message_key, Self::MEGOLM_HKDF_INFO)
    }

    #[cfg(feature = "libolm-compat")]
    fn new_pickle(pickle_key: &[u8]) -> Self {
        Self::new_helper(pickle_key, b"Pickle")
    }

    pub(crate) fn new_helper(message_key: &[u8], info: &[u8]) -> Self {
        let mut expanded_keys = [0u8; 80];

        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), message_key);

        hkdf.expand(info, &mut expanded_keys).expect("Can't expand message key");

        Self(Box::new(expanded_keys))
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CipherKeys {
    aes_key: Box<[u8; 32]>,
    aes_iv: Box<[u8; 16]>,
    mac_key: Box<[u8; 32]>,
}

impl CipherKeys {
    pub fn new(message_key: &[u8; 32]) -> Self {
        let expanded_keys = ExpandedKeys::new(message_key);

        Self::from_expanded_keys(expanded_keys)
    }

    pub fn new_megolm(message_key: &[u8; 128]) -> Self {
        let expanded_keys = ExpandedKeys::new_megolm(message_key);

        Self::from_expanded_keys(expanded_keys)
    }

    #[cfg(feature = "libolm-compat")]
    pub fn new_pickle(pickle_key: &[u8]) -> Self {
        let expanded_keys = ExpandedKeys::new_pickle(pickle_key);

        Self::from_expanded_keys(expanded_keys)
    }

    pub(crate) fn from_expanded_keys(expanded_keys: ExpandedKeys) -> Self {
        let mut aes_key = Box::new([0u8; 32]);
        let mut mac_key = Box::new([0u8; 32]);
        let mut aes_iv = Box::new([0u8; 16]);

        aes_key.copy_from_slice(&expanded_keys.0[0..32]);
        mac_key.copy_from_slice(&expanded_keys.0[32..64]);
        aes_iv.copy_from_slice(&expanded_keys.0[64..80]);

        Self { aes_key, aes_iv, mac_key }
    }

    pub fn aes_key(&self) -> &Aes256Key {
        Aes256Key::from_slice(self.aes_key.as_slice())
    }

    pub const fn mac_key(&self) -> &HmacSha256Key {
        &self.mac_key
    }

    pub fn iv(&self) -> &Aes256Iv {
        Aes256Iv::from_slice(self.aes_iv.as_slice())
    }
}
