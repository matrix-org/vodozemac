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
    unused_qualifications
)]
#![doc = include_str!("../README.md")]

mod cipher;
mod types;
mod utilities;

#[cfg(fuzzing)]
pub mod fuzzing;
pub mod megolm;
pub mod olm;
pub mod sas;

pub use types::{Curve25519KeyError, Curve25519PublicKey, Ed25519PublicKey, SignatureError};

#[derive(Debug, thiserror::Error)]
pub enum LibolmUnpickleError {
    #[error("The pickle uses an unsupported version, expected {0}, got {1}")]
    Version(u32, u32),
    #[error("The pickle didn't contain enough data to be decoded")]
    InvalidSize(#[from] std::io::Error),
    #[error("The pickle wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("The pickle couldn't be decrypted: {0}")]
    Decryption(#[from] crate::cipher::DecryptionError),
    #[error("The pickle contained an invalid ed25519 public key {0}")]
    PublicKey(#[from] SignatureError),
    #[error("The pickle didn't contain a valid Olm session")]
    InvalidSession,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("The message didn't contain a version")]
    MissingVersion,
    #[error("The message was too short, it didn't contain a valid payload")]
    MessageTooShort(usize),
    #[error("The message didn't have a valid version, expected {0}, got {1}")]
    InvalidVersion(u8, u8),
    #[error("The message contained an invalid public key: {0}")]
    InvalidKey(#[from] Curve25519KeyError),
    #[error("The message contained a MAC with an invalid size, expected {0}, got {1}")]
    InvalidMacLength(usize, usize),
    #[error("The message contained an invalid Signature: {0}")]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    ProtoBufError(#[from] prost::DecodeError),
    #[error("The message wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
}
