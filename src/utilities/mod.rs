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

mod libolm_compat;

use base64::{
    DecodeError, Engine, alphabet,
    engine::{GeneralPurpose, general_purpose},
};
pub(crate) use libolm_compat::get_version as get_pickle_version;
#[cfg(feature = "libolm-compat")]
pub(crate) use libolm_compat::{LibolmEd25519Keypair, pickle_libolm, unpickle_libolm};

const STANDARD_NO_PAD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    general_purpose::NO_PAD
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Decode the input as base64 with no padding.
pub fn base64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    STANDARD_NO_PAD.decode(input)
}

/// Encode the input as base64 with no padding.
pub fn base64_encode(input: impl AsRef<[u8]>) -> String {
    STANDARD_NO_PAD.encode(input)
}

pub(crate) fn unpickle<T: for<'b> serde::Deserialize<'b>>(
    ciphertext: &str,
    pickle_key: &[u8; 32],
) -> Result<T, crate::PickleError> {
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

    #[allow(clippy::expect_used)]
    let mut json = serde_json::to_vec(&thing)
        .expect("A pickled object should always be serializable into JSON");
    let cipher = crate::cipher::Cipher::new_pickle(pickle_key);

    let ciphertext = cipher.encrypt_pickle(json.as_slice());

    json.zeroize();

    base64_encode(ciphertext)
}

pub(crate) fn extract_mac(slice: &[u8], truncated: bool) -> crate::cipher::MessageMac {
    use crate::cipher::Mac;

    if truncated {
        let mac_slice = &slice[0..Mac::TRUNCATED_LEN];

        let mut mac = [0u8; Mac::TRUNCATED_LEN];
        mac.copy_from_slice(mac_slice);
        mac.into()
    } else {
        let mac_slice = &slice[0..Mac::LENGTH];

        let mut mac = [0u8; Mac::LENGTH];
        mac.copy_from_slice(mac_slice);
        Mac(mac).into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_b64_decode_any_padding() {
        let encoded_with_padding = "VGhpc0lzQVRlc3Q=";
        let encoded_without_padding = "VGhpc0lzQVRlc3Q";

        let first = base64_decode(encoded_with_padding).expect("Should decode if there is padding");
        let second =
            base64_decode(encoded_without_padding).expect("Should decode if there is no padding");

        assert_eq!(
            first, second,
            "Decoding the same base64 string with and without padding should produce the same result"
        )
    }
}
