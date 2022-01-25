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

pub use base64::DecodeError;
use base64::{decode_config, encode_config, STANDARD_NO_PAD};
use thiserror::Error;

/// Decode the input as base64 with no padding.
pub fn base64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, STANDARD_NO_PAD)
}

/// Encode the input as base64 with no padding.
pub fn base64_encode(input: impl AsRef<[u8]>) -> String {
    encode_config(input, STANDARD_NO_PAD)
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

trait GetVersion {
    fn get_version(&self) -> Option<u32>;
}

impl GetVersion for Vec<u8> {
    fn get_version(&self) -> Option<u32> {
        let version = self.get(0..4)?;
        Some(u32::from_be_bytes(version.try_into().ok()?))
    }
}

pub(crate) trait Decode {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError>
    where
        Self: Sized;
}

#[derive(Debug, Error)]
pub enum LibolmDecodeError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(
        "The decoded value {0} does not fit into the usize type of this \
         architecture"
    )]
    OutSideUsizeRange(u64),
}

impl Decode for u8 {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; 1];

        reader.read_exact(&mut buffer)?;

        Ok(buffer[0])
    }
}

impl Decode for bool {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError> {
        let value = u8::decode(reader)?;

        Ok(value != 0)
    }
}

impl Decode for u32 {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;

        Ok(u32::from_be_bytes(buffer))
    }
}

impl Decode for usize {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError> {
        let size = u32::decode(reader)?;

        size.try_into().map_err(|_| LibolmDecodeError::OutSideUsizeRange(size as u64))
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; N];
        reader.read_exact(&mut buffer)?;

        Ok(buffer)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(reader: &mut impl std::io::Read) -> Result<Self, LibolmDecodeError> {
        let length = usize::decode(reader)?;

        let mut buffer = Vec::with_capacity(length);

        for _ in 0..length {
            let element = T::decode(reader)?;
            buffer.push(element);
        }

        Ok(buffer)
    }
}

pub(crate) fn decrypt_pickle(
    pickle: &[u8],
    pickle_key: &[u8],
) -> Result<Vec<u8>, crate::LibolmUnpickleError> {
    use crate::cipher::Cipher;

    let cipher = Cipher::new_pickle(pickle_key);
    let decoded = base64_decode(pickle)?;

    Ok(cipher.decrypt_pickle(&decoded)?)
}

pub(crate) fn unpickle_libolm<P: Decode, T: TryFrom<P, Error = crate::LibolmUnpickleError>>(
    pickle: &str,
    pickle_key: &str,
    pickle_version: u32,
) -> Result<T, crate::LibolmUnpickleError> {
    let mut decrypted = decrypt_pickle(pickle.as_ref(), pickle_key.as_ref())?;
    let version = decrypted.get_version().ok_or(crate::LibolmUnpickleError::MissingVersion)?;

    if version != pickle_version {
        Err(crate::LibolmUnpickleError::Version(pickle_version, version))
    } else {
        let mut cursor = std::io::Cursor::new(&decrypted);
        let pickle = P::decode(&mut cursor)?;

        zeroize::Zeroize::zeroize(&mut decrypted);

        pickle.try_into()
    }
}
