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

use std::io::Cursor;

use matrix_pickle::Decode;
use zeroize::Zeroize;

use super::base64_decode;
use crate::{cipher::Cipher, LibolmPickleError};

/// Decrypt and decode the given pickle with the given pickle key.
///
/// # Arguments
///
/// * pickle - The base64-encoded and encrypted libolm pickle string
/// * pickle_key - The key that was used to encrypt the libolm pickle
/// * pickle_version - The expected version of the pickle. Unpickling will fail
///   if the version in the pickle doesn't match this one.
pub(crate) fn unpickle_libolm<P: Decode, T: TryFrom<P, Error = LibolmPickleError>>(
    pickle: &str,
    pickle_key: &[u8],
    pickle_version: u32,
) -> Result<T, LibolmPickleError> {
    /// Fetch the pickle version from the given pickle source.
    fn get_version(source: &[u8]) -> Option<u32> {
        // Pickle versions are always u32 encoded as a fixed sized integer in
        // big endian encoding.
        let version = source.get(0..4)?;
        Some(u32::from_be_bytes(version.try_into().ok()?))
    }

    // libolm pickles are always base64 encoded, so first try to decode.
    let decoded = base64_decode(pickle)?;

    // The pickle is always encrypted, even if a zero key is given. Try to
    // decrypt next.
    let cipher = Cipher::new_pickle(pickle_key);
    let mut decrypted = cipher.decrypt_pickle(&decoded)?;

    // A pickle starts with a version, which will decide how we need to decode.
    // We only support the latest version so bail out if it isn't the expected
    // pickle version.
    let version = get_version(&decrypted).ok_or(LibolmPickleError::MissingVersion)?;

    if version == pickle_version {
        let mut cursor = Cursor::new(&decrypted);
        let pickle = P::decode(&mut cursor)?;

        decrypted.zeroize();
        pickle.try_into()
    } else {
        Err(LibolmPickleError::Version(pickle_version, version))
    }
}

#[derive(Zeroize, Decode)]
#[zeroize(drop)]
pub(crate) struct LibolmEd25519Keypair {
    pub public_key: [u8; 32],
    #[secret]
    pub private_key: Box<[u8; 64]>,
}
