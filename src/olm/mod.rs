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

//! An implementation of the Olm double ratchet.
//!
//! ## Overview
//!
//! The core component of the crate is the `Account`, representing a single Olm
//! participant. An Olm `Account` consists of a collection of key pairs, though
//! often documentation will shorten this to just "keys". These are:
//!
//! 1. An Ed25519 *signing key pair* representing the stable cryptographic
//!    identity of the participant (the participant's "fingerprint").
//! 2. A Curve25519 *sender key pair* (also sometimes called the *identity key
//!    pair*, somewhat confusingly).
//! 3. A number of one-time key pairs.
//! 4. A current and previous (if any) "fallback" key pair.
//!
//! While the key in 1 is used for signing but not encryption, the keys in 2-4
//! participate in a triple Diffie-Hellman key exchange (3DH) with another Olm
//! participant, thereby establishing an Olm session on each side of the
//! communication channel. Ultimately, this session is used for deriving the
//! concrete encryption keys for a particular message.
//!
//! Olm sessions are represented by the `Session` struct. Such a session is
//! created by calling `Account::create_outbound_session` on one of the
//! participating accounts, passing it the Curve25519 sender key and one
//! Curve25519 one-time key of the other side. The protocol is asynchronous, so
//! the participant can start sending messages to the other side even before the
//! other side has created a session, producing so-called pre-key messages (see
//! `PreKeyMessage`).
//!
//! Once the other participant receives such a pre-key message, they can create
//! their own matching session by calling `Account::create_inbound_session` and
//! passing it the pre-key message they received and the Curve25519 sender key
//! of the other side. This completes the establishment of the Olm communication
//! channel.
//!
//! ```rust
//! use anyhow::Result;
//! use vodozemac::olm::{Account, InboundCreationResult, OlmMessage, SessionConfig};
//!
//! fn main() -> Result<()> {
//!     let alice = Account::new();
//!     let mut bob = Account::new();
//!
//!     bob.generate_one_time_keys(1);
//!     let bob_otk = *bob.one_time_keys().values().next().unwrap();
//!
//!     let mut alice_session = alice
//!         .create_outbound_session(SessionConfig::version_2(), bob.curve25519_key(), bob_otk);
//!
//!     bob.mark_keys_as_published();
//!
//!     let message = "Keep it between us, OK?";
//!     let alice_msg = alice_session.encrypt(message);
//!
//!     if let OlmMessage::PreKey(m) = alice_msg.clone() {
//!         let result = bob.create_inbound_session(alice.curve25519_key(), &m)?;
//!
//!         let mut bob_session = result.session;
//!         let what_bob_received = result.plaintext;
//!
//!         assert_eq!(alice_session.session_id(), bob_session.session_id());
//!
//!         assert_eq!(message.as_bytes(), what_bob_received);
//!
//!         let bob_reply = "Yes. Take this, it's dangerous out there!";
//!         let bob_encrypted_reply = bob_session.encrypt(bob_reply).into();
//!
//!         let what_alice_received = alice_session
//!             .decrypt(&bob_encrypted_reply)?;
//!         assert_eq!(what_alice_received, bob_reply.as_bytes());
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Sending messages
//!
//! To encrypt a message, just call `Session::encrypt(msg_content)`. This will
//! either produce an `OlmMessage::PreKey(..)` or `OlmMessage::Normal(..)`
//! depending on whether the session is fully established. A session is fully
//! established once you receive (and decrypt) at least one message from the
//! other side.

mod account;
mod messages;
pub(crate) mod session;
mod session_config;
mod session_keys;
mod shared_secret;

pub use account::{
    Account, AccountPickle, IdentityKeys, InboundCreationResult, SessionCreationError,
};
pub use messages::{Message, MessageType, OlmMessage, PreKeyMessage};
pub use session::{ratchet::RatchetPublicKey, DecryptionError, Session, SessionPickle};
pub use session_config::SessionConfig;
pub use session_keys::SessionKeys;
