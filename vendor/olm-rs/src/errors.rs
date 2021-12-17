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

//! A collection of all errors that can be returned by `libolm`.
//!
//! All error enums additionally contain an error named `Unknown`,
//! for returning an error, in case an error is encountered by `libolm`,
//! but no error code is provided.

use std::error::Error;
use std::fmt;
use std::fmt::Debug;

/// Since libolm does not do heap allocation and instead relies on the user to
/// provide already allocated buffers, a lot of potential errors regarding
/// buffer size can be encountered.
/// In most places in this library we create such buffers exactly the way
/// libolm would want, and as such a lot of potential errors would be eliminated.
/// If such an error is still encountered, it would indicate that something else
/// is seriously wrong with the execution environment, so we panic unrecoverably.
pub(crate) fn handle_fatal_error<E>(error: E)
where
    E: Debug,
{
    unreachable!("Encountered fatal error: {:?}", error);
}

pub(crate) fn olm_error() -> usize {
    unsafe { olm_sys::olm_error() }
}

static BAD_ACCOUNT_KEY: &str = "The supplied account key is invalid";
static INVALID_BASE64: &str = "The input base64 was invalid";
static BAD_MSG_KEY_ID: &str = "The message references an unknown key id";
static BAD_MSG_FMT: &str = "The message couldn't be decoded";
static BAD_MSG_MAC: &str = "The message couldn't be decrypted";
static BAD_MSG_VERSION: &str = "The message version is unsupported";
static BAD_SESSION_KEY: &str = "Can't initialise the inbound group session, invalid session key";
static BAD_MSG_INDEX: &str =
    "Can't decode the message, message index is earlier than our earliest known session key";
static NOT_ENOUGH_RAND: &str = "Not enough entropy was supplied";
static BUFFER_SMALL: &str = "Supplied output buffer is too small";
static INPUT_BUFFER_SMALL: &str = "Supplied input buffer is too small";
static UNKNOWN: &str = "An unknown error occured.";

/// All errors that could be caused by an operation regarding an
/// [`OlmAccount`](crate::account::OlmAccount).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmAccountError {
    BadAccountKey,
    BadMessageKeyId,
    InvalidBase64,
    NotEnoughRandom,
    OutputBufferTooSmall,
    Unknown,
}

impl fmt::Display for OlmAccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmAccountError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmAccountError::BadMessageKeyId => BAD_MSG_KEY_ID,
            OlmAccountError::InvalidBase64 => INVALID_BASE64,
            OlmAccountError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmAccountError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmAccountError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

impl Error for OlmAccountError {}
impl Error for OlmSessionError {}
impl Error for OlmGroupSessionError {}
impl Error for OlmPkDecryptionError {}
impl Error for OlmPkSigningError {}

/// All errors that could be caused by an operation regarding [`OlmUitlity`](crate::utility::OlmUtility).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmUtilityError {
    InvalidBase64,
    OutputBufferTooSmall,
    BadMessageMac,
    Unknown,
}

/// All errors that could be caused by an operation regarding an [`OlmSession`](crate::session::OlmSession).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmSessionError {
    BadAccountKey,
    BadMessageFormat,
    BadMessageKeyId,
    BadMessageMac,
    BadMessageVersion,
    InvalidBase64,
    NotEnoughRandom,
    OutputBufferTooSmall,
    Unknown,
}

impl fmt::Display for OlmSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmSessionError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmSessionError::BadMessageKeyId => BAD_MSG_KEY_ID,
            OlmSessionError::BadMessageFormat => BAD_MSG_FMT,
            OlmSessionError::BadMessageMac => BAD_MSG_MAC,
            OlmSessionError::BadMessageVersion => BAD_MSG_VERSION,
            OlmSessionError::InvalidBase64 => INVALID_BASE64,
            OlmSessionError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmSessionError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmSessionError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

/// All errors that could be caused by an operation regarding
/// [`OlmOutboundGroupSession`](crate::outbound_group_session::OlmOutboundGroupSession) and
/// [`OlmInboundGroupSession`](crate::inbound_group_session::OlmInboundGroupSession).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmGroupSessionError {
    BadAccountKey,
    BadMessageFormat,
    BadMessageMac,
    BadMessageVersion,
    BadSessionKey,
    InvalidBase64,
    NotEnoughRandom,
    OutputBufferTooSmall,
    UnknownMessageIndex,
    Unknown,
}

impl fmt::Display for OlmGroupSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmGroupSessionError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmGroupSessionError::BadSessionKey => BAD_SESSION_KEY,
            OlmGroupSessionError::UnknownMessageIndex => BAD_MSG_INDEX,
            OlmGroupSessionError::BadMessageFormat => BAD_MSG_FMT,
            OlmGroupSessionError::BadMessageMac => BAD_MSG_MAC,
            OlmGroupSessionError::BadMessageVersion => BAD_MSG_VERSION,
            OlmGroupSessionError::InvalidBase64 => INVALID_BASE64,
            OlmGroupSessionError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmGroupSessionError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmGroupSessionError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

/// All errors that could be caused by an operation regarding
/// [`OlmSas`](crate::sas::OlmSas).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmSasError {
    NotEnoughRandom,
    OutputBufferTooSmall,
    InputBufferTooSmall,
    OtherPublicKeyUnset,
    InvalidLength,
    Unknown,
}

impl fmt::Display for OlmSasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmSasError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmSasError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmSasError::InputBufferTooSmall => INPUT_BUFFER_SMALL,
            OlmSasError::OtherPublicKeyUnset => "The other public key isn't set",
            OlmSasError::InvalidLength => "The length can't be zero",
            OlmSasError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

/// All errors that could be caused by an operation regarding
/// [`OlmPkSigning`](crate::pk::OlmPkSigning).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmPkSigningError {
    InvalidSeed,
    OutputBufferTooSmall,
    InputBufferTooSmall,
    Unknown,
}

impl fmt::Display for OlmPkSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmPkSigningError::InvalidSeed => "The given seed is too short",
            OlmPkSigningError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmPkSigningError::InputBufferTooSmall => INPUT_BUFFER_SMALL,
            OlmPkSigningError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

impl From<&str> for OlmPkSigningError {
    fn from(value: &str) -> Self {
        match value {
            "OUTPUT_BUFFER_TOO_SMALL" => OlmPkSigningError::OutputBufferTooSmall,
            "INPUT_BUFFER_TOO_SMALL" => OlmPkSigningError::OutputBufferTooSmall,
            _ => OlmPkSigningError::Unknown,
        }
    }
}

/// All errors that could be caused by an operation regarding
/// [`OlmPkEncryption`](crate::pk::OlmPkEncryption).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmPkEncryptionError {
    OutputBufferTooSmall,
    InputBufferTooSmall,
    Unknown,
}

impl fmt::Display for OlmPkEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmPkEncryptionError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmPkEncryptionError::InputBufferTooSmall => INPUT_BUFFER_SMALL,
            OlmPkEncryptionError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

impl From<&str> for OlmPkEncryptionError {
    fn from(value: &str) -> Self {
        match value {
            "OUTPUT_BUFFER_TOO_SMALL" => OlmPkEncryptionError::OutputBufferTooSmall,
            "INPUT_BUFFER_TOO_SMALL" => OlmPkEncryptionError::OutputBufferTooSmall,
            _ => OlmPkEncryptionError::Unknown,
        }
    }
}

/// All errors that could be caused by an operation regarding
/// [`OlmPkDecryption`](crate::pk::OlmPkDecryption).
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmPkDecryptionError {
    BadAccountKey,
    BadMessageMac,
    InvalidBase64,
    OutputBufferTooSmall,
    InputBufferTooSmall,
    Unknown(String),
}

impl fmt::Display for OlmPkDecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmPkDecryptionError::InvalidBase64 => INVALID_BASE64,
            OlmPkDecryptionError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmPkDecryptionError::BadMessageMac => BAD_MSG_MAC,
            OlmPkDecryptionError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmPkDecryptionError::InputBufferTooSmall => INPUT_BUFFER_SMALL,
            OlmPkDecryptionError::Unknown(e) => e,
        };
        write!(f, "{}", message)
    }
}

impl From<&str> for OlmPkDecryptionError {
    fn from(value: &str) -> Self {
        match value {
            "INVALID_BASE64" => OlmPkDecryptionError::InvalidBase64,
            "BAD_MESSAGE_MAC" => OlmPkDecryptionError::BadMessageMac,
            "BAD_ACCOUNT_KEY" => OlmPkDecryptionError::BadAccountKey,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmPkDecryptionError::OutputBufferTooSmall,
            "INPUT_BUFFER_TOO_SMALL" => OlmPkDecryptionError::OutputBufferTooSmall,
            m => OlmPkDecryptionError::Unknown(m.to_owned()),
        }
    }
}
