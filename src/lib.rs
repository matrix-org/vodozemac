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

//! A Rust implementation of Olm and Megolm
//!
//! vodozemac is a Rust reimplementation of
//! [libolm](https://gitlab.matrix.org/matrix-org/olm), a cryptographic library
//! used for end-to-end encryption in [Matrix](https://matrix.org). At its core, it
//! is an implementation of the Olm and Megolm cryptographic ratchets, along
//! with a high-level API to easily establish cryptographic communication
//! channels employing those ratchets with other parties. It also implements
//! some other miscellaneous cryptographic functionality which is useful for
//! building Matrix clients, such as [SAS][sas].
//!
//! [sas]:
//! <https://spec.matrix.org/v1.2/client-server-api/#short-authentication-string-sas-verification>
//!
//! # Olm
//!
//! Olm is an implementation of the [Double Ratchet
//! algorithm](https://whispersystems.org/docs/specifications/doubleratchet/), very
//! similar to that employed by the Signal Protocol. It allows the establishment
//! of a 1-to-1 private communication channel, with perfect forward secrecy and
//! self-healing properties.
//!
//! A detailed technical specification can be found at
//! <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>.
//!
//! For more information on using vodozemac for Olm, see the [`olm`] module.
//!
//! # Megolm
//!
//! Megolm is an AES-based single ratchet for group conversations with a large
//! number of participants, where using Olm would be cost prohibitive because it
//! would imply encrypting each message individually for each participant.
//! Megolm sidesteps this by encrypting messages with a symmetric ratchet,
//! shared once with each participant and then reused for a sequence of messages
//! before rotating.
//!
//! This is a trade-off in which we lose Olm's self-healing properties, because
//! someone in possession of a Megolm session at a particular state can derive
//! all future states. However, if the attacker is only able to obtain the
//! session in a ratcheted state, they cannot use it to decrypt messages
//! encrypted with an earlier state. This preserves forward secrecy.
//!
//! A detailed technical specification can be found at
//! <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>.
//!
//! For more information on using vodozemac for Megolm, see the [`megolm`]
//! module.
//!
//! # Features
//!
//! ## Supported
//!
//! - [Olm](https://matrix-org.github.io/vodozemac/vodozemac/olm/index.html)
//! - [Megolm](https://matrix-org.github.io/vodozemac/vodozemac/megolm/index.html)
//! - [libolm pickle format](#legacy-pickles) (read-only)
//! - [Modern pickle format](#modern-pickles)
//! - [SAS (Short Authentication Strings)](https://matrix-org.github.io/vodozemac/vodozemac/sas/index.html)
//!
//! ## Unsupported
//!
//! - Creating asymmetric [server-side message key
//!   backups][legacy-message-key-backup], since they are slated to be replaced
//!   with symmetric backups.
//!
//! ## Planned
//!
//! - Symmetric [server-side message key backups][symmetric-message-key-backup]
//! - Importing asymmetric [server-side message key
//!   backups][legacy-message-key-backup], for compatibility with existing
//!   backups created by libolm.
//!
//! [legacy-message-key-backup]:
//! <https://spec.matrix.org/v1.2/client-server-api/#server-side-key-backups>
//!
//! [symmetric-message-key-backup]:
//! https://github.com/uhoreg/matrix-doc/blob/symmetric-backups/proposals/3270-symmetric-megolm-backup.md
//!
//! # Feature flags
//!
//! ## Low-level API
//!
//! Feature: `low-level-api` (default: off)
//!
//! Vodozemac exposes some lower-level structs and functions that are only
//! useful in very advanced use cases. These should *not* be needed by the vast
//! majority of users.
//!
//! Extreme care must be taken when using such APIs, as incorrect usage can lead
//! to broken sessions.
//!
//! # Pickling
//!
//! vodozemac supports serializing its entire internal state into a form
//! a "pickle". The state can subsequently be restored from such a pickle
//! ("unpickled") in order to continue operation. This is used to support some
//! Matrix features like device dehydration.
//!
//! ## Legacy pickles
//!
//! The legacy pickle format is a simple binary format used by libolm.
//! Implemented for interoperability with current clients which are using
//! libolm. Only *unpickling* is supported.
//!
//! ## Modern pickles
//!
//! The crate also implements a modern pickling mechanism using
//! [Serde](https://serde.rs/). The exact serialization format is not mandated
//! nor specified by this crate, but you can serialize to and deserialize from
//! any format supported by Serde.
//!
//! The following structs support pickling:
//!
//! - [`olm::Account`]
//! - [`olm::Session`]
//! - [`megolm::GroupSession`]
//! - [`megolm::InboundGroupSession`]
//!
//! For example, the following will print out the JSON representing the
//! serialized `Account` and will leave no new copies of the account's secrets
//! in memory:
//!
//! ```rust
//! use anyhow::Result;
//! use vodozemac::olm::{Account, AccountPickle};
//!
//! const PICKLE_KEY: [u8; 32] = [0u8; 32];
//!
//! fn main() -> Result<()>{
//!     let mut account = Account::new();
//!
//!     account.generate_one_time_keys(10);
//!     account.generate_fallback_key();
//!
//!     let pickle = account.pickle().encrypt(&PICKLE_KEY);
//!
//!     let account2: Account = AccountPickle::from_encrypted(&pickle, &PICKLE_KEY)?.into();
//!
//!     assert_eq!(account.identity_keys(), account2.identity_keys());
//!
//!     Ok(())
//! }
//! ```
//!
//! You can unpickle a pickle-able struct directly from its serialized form:
//!
//! ```rust
//! # use anyhow::Result;
//! # use vodozemac::olm::{Account, AccountPickle};
//! # use zeroize::Zeroize;
//! #
//! # fn main() -> Result<()> {
//! #   let some_account = Account::new();
//!     let mut json_str = serde_json::to_string(&some_account.pickle())?;
//!     // This will produce an account which is identical to `some_account`.
//!     let account: Account = serde_json::from_str::<AccountPickle>(&json_str)?.into();
//!
//!     json_str.zeroize();
//! #
//! #    Ok(())
//! # }
//! ```
//!
//! However, the pickle-able structs do not implement `serde::Serialize`
//! themselves. If you want to serialize to a format other than JSON, you should
//! instead call the `.pickle()` method to obtain a special serializable struct.
//! This struct *does* implement `Serialize` and can therefore be serialized
//! into any format supported by `serde`. To get back to the original struct
//! from such as serializeable struct, just call `.unpickle()`.
//!
//! ```rust
//! use anyhow::Result;
//! use vodozemac::olm::Account;
//!
//! fn main() -> Result<()> {
//!     let account = Account::new();
//!     let account: Account = account.pickle().into();  // this is identity
//!
//!     Ok(())
//! }
//! ```

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
    Curve25519PublicKey, Curve25519SecretKey, Ed25519Keypair, Ed25519PublicKey, Ed25519SecretKey,
    Ed25519Signature, KeyError, KeyId, SharedSecret, SignatureError,
};
pub use utilities::{base64_decode, base64_encode};

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
    /// The serialized Vodozemac object couldn't be deserialized.
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
    Decode(#[from] matrix_pickle::DecodeError),
    /// The object could not be encoded as a pickle.
    #[error(transparent)]
    Encode(#[from] matrix_pickle::EncodeError),
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

/// The version of vodozemac that is being used.
pub static VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
fn corpus_data_path(fuzz_target: &str) -> std::path::PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("Cargo always sets the manifest dir");

    let mut afl_dir = std::path::PathBuf::from(manifest_dir);
    afl_dir.push("afl");
    afl_dir.push(fuzz_target);
    afl_dir.push("in");

    afl_dir
}

#[cfg(test)]
fn run_corpus<F>(fuzz_target: &str, method: F)
where
    F: FnOnce(&[u8]) + Copy,
{
    let dir = corpus_data_path(fuzz_target);
    let corpus = std::fs::read_dir(dir).expect("Couldn't read the corpus directory");

    for input in corpus {
        let input = input.expect("Couldn't read the input file");
        let data = std::fs::read(input.path()).expect("Couldn't read the input file");
        method(&data)
    }
}
