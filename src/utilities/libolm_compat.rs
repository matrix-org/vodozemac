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

use std::io::{Cursor, Read};

use thiserror::Error;
use zeroize::Zeroize;

use super::base64_decode;
use crate::{cipher::Cipher, LibolmUnpickleError};

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
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError>
    where
        Self: Sized;
}

impl Decode for u8 {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; 1];

        reader.read_exact(&mut buffer)?;

        Ok(buffer[0])
    }
}

impl Decode for bool {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let value = u8::decode(reader)?;

        Ok(value != 0)
    }
}

impl Decode for u32 {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;

        Ok(u32::from_be_bytes(buffer))
    }
}

impl Decode for usize {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let size = u32::decode(reader)?;

        size.try_into().map_err(|_| LibolmDecodeError::OutSideUsizeRange(size as u64))
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
        let mut buffer = [0u8; N];
        reader.read_exact(&mut buffer)?;

        Ok(buffer)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(reader: &mut impl Read) -> Result<Self, LibolmDecodeError> {
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
) -> Result<Vec<u8>, LibolmUnpickleError> {
    let cipher = Cipher::new_pickle(pickle_key);
    let decoded = base64_decode(pickle)?;

    Ok(cipher.decrypt_pickle(&decoded)?)
}

pub(crate) fn unpickle_libolm<P: Decode, T: TryFrom<P, Error = LibolmUnpickleError>>(
    pickle: &str,
    pickle_key: &str,
    pickle_version: u32,
) -> Result<T, LibolmUnpickleError> {
    let mut decrypted = decrypt_pickle(pickle.as_ref(), pickle_key.as_ref())?;
    let version = decrypted.get_version().ok_or(LibolmUnpickleError::MissingVersion)?;

    if version != pickle_version {
        Err(LibolmUnpickleError::Version(pickle_version, version))
    } else {
        let mut cursor = Cursor::new(&decrypted);
        let pickle = P::decode(&mut cursor)?;

        decrypted.zeroize();

        pickle.try_into()
    }
}
