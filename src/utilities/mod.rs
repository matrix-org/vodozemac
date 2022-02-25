// Copyright 2021 The Matrix.org Foundation C.I.C.
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

#[cfg(feature = "libolm-compat")]
mod libolm_compat;

pub use base64::DecodeError;
#[cfg(feature = "libolm-compat")]
pub(crate) use libolm_compat::{unpickle_libolm, Decode, DecodeSecret, LibolmDecodeError};

/// Decode the input as base64 with no padding.
pub fn base64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    base64::decode_config(input, base64::STANDARD_NO_PAD)
}

/// Encode the input as base64 with no padding.
pub fn base64_encode(input: impl AsRef<[u8]>) -> String {
    base64::encode_config(input, base64::STANDARD_NO_PAD)
}

pub(crate) fn unpickle<T: for<'b> serde::Deserialize<'b>>(
    ciphertext: &str,
    pickle_key: &[u8; 32],
) -> Result<T, crate::UnpickleError> {
    use zeroize::Zeroize;

    let cipher = crate::cipher::Cipher::new_pickle(pickle_key);
    let decoded = base64_decode(ciphertext)?;
    let mut plaintext = cipher.decrypt_pickle(&decoded)?;

    let pickle = serde_json::from_slice(&plaintext)?;

    plaintext.zeroize();

    Ok(pickle)
}

pub(crate) fn pickle<T: serde::Serialize>(thing: &T, pickle_key: &[u8; 32]) -> String {
    use zeroize::Zeroize;

    let mut json = serde_json::to_vec(&thing).expect("Can't serialize a pickled object");
    let cipher = crate::cipher::Cipher::new_pickle(pickle_key);

    let ciphertext = cipher.encrypt_pickle(json.as_slice());

    json.zeroize();

    base64_encode(ciphertext)
}

// The integer encoding logic here has been taken from the integer-encoding[1]
// crate and is under the MIT license.
//
// The MIT License (MIT)
//
// Copyright (c) 2016 Google Inc. (lewinb@google.com) -- though not an official
// Google product or in any way related!
// Copyright (c) 2018-2020 Lewin Bormann (lbo@spheniscida.de)
//
// [1]: https://github.com/dermesser/integer-encoding-rs
pub(crate) trait VarInt {
    fn to_var_int(self) -> Vec<u8>;
}

/// Most-significant byte, == 0x80
const MSB: u8 = 0b1000_0000;

/// How many bytes an integer uses when being encoded as a VarInt.
#[inline]
fn required_encoded_space_unsigned(mut v: u64) -> usize {
    if v == 0 {
        return 1;
    }

    let mut logcounter = 0;
    while v > 0 {
        logcounter += 1;
        v >>= 7;
    }
    logcounter
}

impl VarInt for usize {
    fn to_var_int(self) -> Vec<u8> {
        (self as u64).to_var_int()
    }
}

impl VarInt for u32 {
    fn to_var_int(self) -> Vec<u8> {
        (self as u64).to_var_int()
    }
}

impl VarInt for u64 {
    #[inline]
    fn to_var_int(self) -> Vec<u8> {
        let mut v = Vec::new();
        v.resize(required_encoded_space_unsigned(self), 0);

        let mut n = self;
        let mut i = 0;

        while n >= 0x80 {
            v[i] = MSB | (n as u8);
            i += 1;
            n >>= 7;
        }

        v[i] = n as u8;

        v
    }
}
