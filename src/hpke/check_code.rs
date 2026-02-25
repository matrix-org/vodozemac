// Copyright 2026 The Matrix.org Foundation C.I.C.
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

/// A check code that can be used to confirm that two [`EstablishedHpkeChannel`]
/// objects share the same secret. This is supposed to be shared out-of-band to
/// protect against active MITM attacks.
///
/// Since the initiator device can always tell whether a MITM attack is in
/// progress after channel establishment, this code technically carries only a
/// single bit of information, representing whether the initiator has determined
/// that the channel is "secure" or "not secure".
///
/// However, given this will need to be interactively confirmed by the user,
/// there is risk that the user would confirm the dialogue without paying
/// attention to its content. By expanding this single bit into a deterministic
/// two-digit check code, the user is forced to pay more attention by having to
/// enter it instead of just clicking through a dialogue.
///
/// An example protocol which uses the [`CheckCode`] for out of band
/// confirmation can be found in [MSC4108] and [MSC4388].
///
/// [MSC4108]: https://github.com/matrix-org/matrix-spec-proposals/pull/4108
/// [MSC4388]: https://github.com/matrix-org/matrix-spec-proposals/pull/4388
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckCode {
    pub(crate) bytes: [u8; 2],
}

impl CheckCode {
    /// Convert the check code to an array of two bytes.
    ///
    /// The bytes can be converted to a more user-friendly representation. The
    /// [`CheckCode::to_digit`] converts the bytes to a two-digit number.
    pub const fn as_bytes(&self) -> &[u8; 2] {
        &self.bytes
    }

    /// Convert the check code to two base-10 numbers.
    ///
    /// The number should be displayed with a leading 0 in case the first digit
    /// is a 0.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use vodozemac::hpke::CheckCode;
    /// # let check_code: CheckCode = unimplemented!();
    /// let check_code = check_code.to_digit();
    ///
    /// println!("The check code of the HPKE channel is: {check_code:02}");
    /// ```
    pub const fn to_digit(&self) -> u8 {
        let first = (self.bytes[0] % 10) * 10;
        let second = self.bytes[1] % 10;

        first + second
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn check_code() {
        let check_code = CheckCode { bytes: [0x0, 0x0] };
        let digit = check_code.to_digit();
        assert_eq!(digit, 0, "Two zero bytes should generate a 0 digit");
        assert_eq!(
            check_code.as_bytes(),
            &[0x0, 0x0],
            "CheckCode::as_bytes() should return the exact bytes we generated."
        );

        let check_code = CheckCode { bytes: [0x9, 0x9] };
        let digit = check_code.to_digit();
        assert_eq!(
            check_code.as_bytes(),
            &[0x9, 0x9],
            "CheckCode::as_bytes() should return the exact bytes we generated."
        );
        assert_eq!(digit, 99);

        let check_code = CheckCode { bytes: [0xff, 0xff] };
        let digit = check_code.to_digit();
        assert_eq!(
            check_code.as_bytes(),
            &[0xff, 0xff],
            "CheckCode::as_bytes() should return the exact bytes we generated."
        );
        assert_eq!(digit, 55, "u8::MAX should generate 55");
    }

    proptest! {
        #[test]
        fn check_code_proptest(bytes in prop::array::uniform2(0u8..) ) {
            let check_code = CheckCode {
                bytes
            };

            let digit = check_code.to_digit();

            prop_assert!(
                (0..=99).contains(&digit),
                "The digit should be in the 0-99 range"
            );
        }
    }
}
