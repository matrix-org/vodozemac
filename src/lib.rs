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

#![deny(
    clippy::mem_forget,
    clippy::unwrap_used,
    dead_code,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unsafe_op_in_unsafe_fn,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    rust_2018_idioms
)]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod cipher;
mod types;
mod utilities;

pub mod hazmat;
pub mod megolm;
pub mod olm;
pub mod sas;

pub use base64::DecodeError as Base64DecodeError;
pub use prost::DecodeError as ProtoBufDecodeError;
pub use types::{
    Curve25519PublicKey, Ed25519Keypair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature,
    KeyError, KeyId, SignatureError,
};

/// Error type describing the various ways Vodozemac pickles can fail to be
/// decoded.
#[derive(Debug, thiserror::Error)]
pub enum PickleError {
    /// The pickle wasn't valid base64.
    #[error("The pickle wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The encrypted pickle could not have been decrypted.
    #[error("The pickle couldn't be decrypted: {0}")]
    Decryption(#[from] crate::cipher::DecryptionError),
    /// The serialized Vodozemac object couldn't be deserialzied.
    #[error("The pickle couldn't be deserialized: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Error type describing the various ways libolm pickles can fail to be
/// decoded.
#[cfg(feature = "libolm-compat")]
#[derive(Debug, thiserror::Error)]
pub enum LibolmPickleError {
    /// The pickle is missing a valid version.
    #[error("The pickle doesn't contain a version")]
    MissingVersion,
    /// The pickle has a unsupported version.
    #[error("The pickle uses an unsupported version, expected {0}, got {1}")]
    Version(u32, u32),
    /// The pickle wasn't valid base64.
    #[error("The pickle wasn't valid base64: {0}")]
    Base64(#[from] Base64DecodeError),
    /// The pickle could not have been decrypted.
    #[error("The pickle couldn't be decrypted: {0}")]
    Decryption(#[from] crate::cipher::DecryptionError),
    /// The pickle contains an invalid public key.
    #[error("The pickle contained an invalid ed25519 public key {0}")]
    PublicKey(#[from] KeyError),
    /// The pickle does not contain a valid receiving or sending chain. A valid
    /// Olm session needs to have at least one of them.
    #[error("The pickle didn't contain a valid Olm session")]
    InvalidSession,
    /// The payload of the pickle could not be decoded.
    #[error(transparent)]
    Decode(#[from] crate::utilities::LibolmDecodeError),
}

/// Error type describing the different ways message decoding can fail.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The Olm message has an invalid type.
    #[error("The message has an invalid type, expected 0 or 1, got {0}")]
    MessageType(usize),
    /// The message is missing a valid version.
    #[error("The message didn't contain a version")]
    MissingVersion,
    /// The message doesn't have enough data to be correctly decoded.
    #[error("The message was too short, it didn't contain a valid payload")]
    MessageTooShort(usize),
    /// The message has a unsupported version.
    #[error("The message didn't have a valid version, expected {0}, got {1}")]
    InvalidVersion(u8, u8),
    /// An embedded public key couldn't be decoded.
    #[error("The message contained an invalid public key: {0}")]
    InvalidKey(#[from] KeyError),
    /// The embedded message authentication code couldn't be decoded.
    #[error("The message contained a MAC with an invalid size, expected {0}, got {1}")]
    InvalidMacLength(usize, usize),
    /// An embedded signature couldn't be decoded.
    #[error("The message contained an invalid Signature: {0}")]
    Signature(#[from] SignatureError),
    /// The message couldn't be decoded as a valid protocol buffer message.
    #[error(transparent)]
    ProtoBufError(#[from] ProtoBufDecodeError),
    /// The message wasn't valid base64.
    #[error("The message wasn't valid base64: {0}")]
    Base64(#[from] Base64DecodeError),
}
