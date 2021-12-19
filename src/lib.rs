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

mod account;
mod cipher;
mod session;
mod session_keys;
mod shared_secret;
mod types;
mod utilities;

pub mod megolm;
pub mod messages;
pub mod sas;

pub use account::Account;
pub use session::Session;

pub use crate::types::{Curve25519KeyError, Curve25519PublicKey};

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
    PublicKey(#[from] ed25519_dalek::SignatureError),
    #[error("The pickle didn't contain a valid Olm session")]
    InvalidSession,
}
