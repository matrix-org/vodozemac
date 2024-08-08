// Copyright 2021 Damir Jelić
// Copyright 2021 The Matrix.org Foundation C.I.C.
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

mod chain_key;
mod double_ratchet;
pub mod message_key;
pub mod ratchet;
mod receiver_chain;
mod root_key;

use std::fmt::Debug;

use aes::cipher::block_padding::UnpadError;
use arrayvec::ArrayVec;
use chain_key::RemoteChainKey;
use double_ratchet::DoubleRatchet;
use hmac::digest::MacError;
use ratchet::RemoteRatchetKey;
use receiver_chain::ReceiverChain;
use root_key::RemoteRootKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    session_config::Version,
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    SessionConfig,
};
#[cfg(feature = "low-level-api")]
use crate::hazmat::olm::MessageKey;
use crate::{
    olm::{
        messages::{Message, OlmMessage, PreKeyMessage},
        session::double_ratchet::RatchetCount,
    },
    utilities::{pickle, unpickle},
    Curve25519PublicKey, PickleError,
};

const MAX_RECEIVING_CHAINS: usize = 5;

/// Error type for Olm-based decryption failures.
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// The message authentication code of the message was invalid.
    #[error("Failed decrypting Olm message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),
    /// The length of the message authentication code of the message did not
    /// match our expected length.
    #[error("Failed decrypting Olm message, invalid MAC length: expected {0}, got {1}")]
    InvalidMACLength(usize, usize),
    /// The ciphertext of the message isn't padded correctly.
    #[error("Failed decrypting Olm message, invalid padding")]
    InvalidPadding(#[from] UnpadError),
    /// The session is missing the correct message key to decrypt the message,
    /// either because it was already used up, or because the Session has been
    /// ratcheted forwards and the message key has been discarded.
    #[error("The message key with the given key can't be created, message index: {0}")]
    MissingMessageKey(u64),
    /// Too many messages have been skipped to attempt decrypting this message.
    #[error("The message gap was too big, got {0}, max allowed {1}")]
    TooBigMessageGap(u64, u64),
}

#[derive(Serialize, Deserialize, Clone)]
struct ChainStore {
    inner: ArrayVec<ReceiverChain, MAX_RECEIVING_CHAINS>,
}

impl ChainStore {
    fn new() -> Self {
        Self { inner: ArrayVec::new() }
    }

    fn push(&mut self, ratchet: ReceiverChain) {
        if self.inner.is_full() {
            self.inner.pop_at(0);
        }

        self.inner.push(ratchet)
    }

    const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[cfg(test)]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    #[cfg(feature = "libolm-compat")]
    pub fn get(&self, index: usize) -> Option<&ReceiverChain> {
        self.inner.get(index)
    }

    fn find_ratchet(&mut self, ratchet_key: &RemoteRatchetKey) -> Option<&mut ReceiverChain> {
        self.inner.iter_mut().find(|r| r.belongs_to(ratchet_key))
    }
}

impl Default for ChainStore {
    fn default() -> Self {
        Self::new()
    }
}

/// An Olm session represents one end of an encrypted communication channel
/// between two participants.
///
/// A session enables enables the session owner to encrypt messages intended
/// for, and decrypt messages sent by, the other participant of the channel.
///
/// Olm sessions have two important properties:
///
/// 1. They are based on a double ratchet algorithm which continuously
///    introduces new entropy into the channel as messages are sent and
///    received. This imbues the channel with *self-healing* properties,
///    allowing it to recover from a momentary loss of confidentiality in the
///    event of a key compromise.
/// 2. They are *asynchronous*, allowing the participant to start sending
///    messages to the other side even if the other participant is not online at
///    the moment.
///
/// An Olm [`Session`] is acquired from an [`Account`], by calling either
///
/// - [`Account::create_outbound_session`], if you are the first participant to
///   send a message in this channel, or
/// - [`Account::create_inbound_session`], if the other participant initiated
///   the channel by sending you a message.
///
/// [`Account`]: crate::olm::Account
/// [`Account::create_outbound_session`]: crate::olm::Account::create_outbound_session
/// [`Account::create_inbound_session`]: crate::olm::Account::create_inbound_session
pub struct Session {
    session_keys: SessionKeys,
    sending_ratchet: DoubleRatchet,
    receiving_chains: ChainStore,
    config: SessionConfig,
}

impl Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { session_keys: _, sending_ratchet, receiving_chains, config } = self;

        f.debug_struct("Session")
            .field("session_id", &self.session_id())
            .field("sending_ratchet", &sending_ratchet)
            .field("receiving_chains", &receiving_chains.inner)
            .field("config", config)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(super) fn new(
        config: SessionConfig,
        shared_secret: Shared3DHSecret,
        session_keys: SessionKeys,
    ) -> Self {
        let local_ratchet = DoubleRatchet::active(shared_secret);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_chains: Default::default(),
            config,
        }
    }

    pub(super) fn new_remote(
        config: SessionConfig,
        shared_secret: RemoteShared3DHSecret,
        remote_ratchet_key: Curve25519PublicKey,
        session_keys: SessionKeys,
    ) -> Self {
        let (root_key, remote_chain_key) = shared_secret.expand();

        let remote_ratchet_key = RemoteRatchetKey::from(remote_ratchet_key);
        let root_key = RemoteRootKey::new(root_key);
        let remote_chain_key = RemoteChainKey::new(remote_chain_key);

        let local_ratchet = DoubleRatchet::inactive_from_prekey_data(root_key, remote_ratchet_key);
        let remote_ratchet =
            ReceiverChain::new(remote_ratchet_key, remote_chain_key, RatchetCount::new());

        let mut ratchet_store = ChainStore::new();
        ratchet_store.push(remote_ratchet);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_chains: ratchet_store,
            config,
        }
    }

    /// Returns the globally unique session ID, in base64-encoded form.
    ///
    /// This is a shorthand helper of the [`SessionKeys::session_id()`] method.
    pub fn session_id(&self) -> String {
        self.session_keys.session_id()
    }

    /// Have we ever received and decrypted a message from the other side?
    ///
    /// Used to decide if outgoing messages should be sent as normal or pre-key
    /// messages.
    pub const fn has_received_message(&self) -> bool {
        !self.receiving_chains.is_empty()
    }

    /// Encrypt the `plaintext` and construct an [`OlmMessage`].
    ///
    /// The message will either be a pre-key message or a normal message,
    /// depending on whether the session is fully established. A session is
    /// fully established once you receive (and decrypt) at least one
    /// message from the other side.
    pub fn encrypt(&mut self, plaintext: impl AsRef<[u8]>) -> OlmMessage {
        let message = match self.config.version {
            Version::V1 => self.sending_ratchet.encrypt_truncated_mac(plaintext.as_ref()),
            Version::V2 => self.sending_ratchet.encrypt(plaintext.as_ref()),
        };

        if self.has_received_message() {
            OlmMessage::Normal(message)
        } else {
            let message = PreKeyMessage::new(self.session_keys, message);

            OlmMessage::PreKey(message)
        }
    }

    /// Get the keys associated with this session.
    pub const fn session_keys(&self) -> SessionKeys {
        self.session_keys
    }

    pub const fn session_config(&self) -> SessionConfig {
        self.config
    }

    /// Get the [`MessageKey`] to encrypt the next message.
    ///
    /// **Note**: Each key obtained in this way should be used to encrypt
    /// a message and the message must then be sent to the recipient.
    ///
    /// Failing to do so will increase the number of out-of-order messages on
    /// the recipient side. Given that a `Session` can only support a limited
    /// number of out-of-order messages, this will eventually lead to
    /// undecryptable messages.
    #[cfg(feature = "low-level-api")]
    pub fn next_message_key(&mut self) -> MessageKey {
        self.sending_ratchet.next_message_key()
    }

    /// Try to decrypt an Olm message, which will either return the plaintext or
    /// result in a [`DecryptionError`].
    ///
    /// [`DecryptionError`]: self::DecryptionError
    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<Vec<u8>, DecryptionError> {
        let decrypted = match message {
            OlmMessage::Normal(m) => self.decrypt_decoded(m)?,
            OlmMessage::PreKey(m) => self.decrypt_decoded(&m.message)?,
        };

        Ok(decrypted)
    }

    pub(super) fn decrypt_decoded(
        &mut self,
        message: &Message,
    ) -> Result<Vec<u8>, DecryptionError> {
        let ratchet_key = RemoteRatchetKey::from(message.ratchet_key);

        if let Some(ratchet) = self.receiving_chains.find_ratchet(&ratchet_key) {
            ratchet.decrypt(message, &self.config)
        } else {
            let (sending_ratchet, mut remote_ratchet) = self.sending_ratchet.advance(ratchet_key);

            let plaintext = remote_ratchet.decrypt(message, &self.config)?;

            self.sending_ratchet = sending_ratchet;
            self.receiving_chains.push(remote_ratchet);

            Ok(plaintext)
        }
    }

    /// Convert the session into a struct which implements [`serde::Serialize`]
    /// and [`serde::Deserialize`].
    pub fn pickle(&self) -> SessionPickle {
        SessionPickle {
            session_keys: self.session_keys,
            sending_ratchet: self.sending_ratchet.clone(),
            receiving_chains: self.receiving_chains.clone(),
            config: self.config,
        }
    }

    /// Restore a [`Session`] from a previously saved [`SessionPickle`].
    pub fn from_pickle(pickle: SessionPickle) -> Self {
        pickle.into()
    }

    /// Create a [`Session`] object by unpickling a session pickle in libolm
    /// legacy pickle format.
    ///
    /// Such pickles are encrypted and need to first be decrypted using
    /// `pickle_key`.
    #[cfg(feature = "libolm-compat")]
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, crate::LibolmPickleError> {
        use crate::{olm::session::libolm_compat::Pickle, utilities::unpickle_libolm};

        const PICKLE_VERSION: u32 = 1;
        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
    }
}

#[cfg(feature = "libolm-compat")]
mod libolm_compat {
    use matrix_pickle::Decode;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        chain_key::{ChainKey, RemoteChainKey},
        double_ratchet::{DoubleRatchet, RatchetCount},
        message_key::RemoteMessageKey,
        ratchet::{Ratchet, RatchetKey, RemoteRatchetKey},
        receiver_chain::ReceiverChain,
        root_key::{RemoteRootKey, RootKey},
        ChainStore, Session,
    };
    use crate::{
        olm::{SessionConfig, SessionKeys},
        types::Curve25519SecretKey,
        Curve25519PublicKey,
    };

    #[derive(Debug, Decode, Zeroize, ZeroizeOnDrop)]
    struct SenderChain {
        public_ratchet_key: [u8; 32],
        #[secret]
        secret_ratchet_key: Box<[u8; 32]>,
        chain_key: Box<[u8; 32]>,
        chain_key_index: u32,
    }

    #[derive(Debug, Decode, Zeroize, ZeroizeOnDrop)]
    struct ReceivingChain {
        public_ratchet_key: [u8; 32],
        #[secret]
        chain_key: Box<[u8; 32]>,
        chain_key_index: u32,
    }

    impl From<&ReceivingChain> for ReceiverChain {
        fn from(chain: &ReceivingChain) -> Self {
            let ratchet_key = RemoteRatchetKey::from(chain.public_ratchet_key);
            let chain_key = RemoteChainKey::from_bytes_and_index(
                chain.chain_key.clone(),
                chain.chain_key_index,
            );

            ReceiverChain::new(ratchet_key, chain_key, RatchetCount::unknown())
        }
    }

    #[derive(Debug, Decode, Zeroize, ZeroizeOnDrop)]
    struct MessageKey {
        ratchet_key: [u8; 32],
        #[secret]
        message_key: Box<[u8; 32]>,
        index: u32,
    }

    impl From<&MessageKey> for RemoteMessageKey {
        fn from(key: &MessageKey) -> Self {
            RemoteMessageKey { key: key.message_key.clone(), index: key.index.into() }
        }
    }

    #[derive(Decode)]
    pub(super) struct Pickle {
        #[allow(dead_code)]
        version: u32,
        #[allow(dead_code)]
        received_message: bool,
        session_keys: SessionKeys,
        #[secret]
        root_key: Box<[u8; 32]>,
        sender_chains: Vec<SenderChain>,
        receiver_chains: Vec<ReceivingChain>,
        message_keys: Vec<MessageKey>,
    }

    impl Drop for Pickle {
        fn drop(&mut self) {
            self.root_key.zeroize();
            self.sender_chains.zeroize();
            self.receiver_chains.zeroize();
            self.message_keys.zeroize();
        }
    }

    impl TryFrom<Pickle> for Session {
        type Error = crate::LibolmPickleError;

        fn try_from(pickle: Pickle) -> Result<Self, Self::Error> {
            let mut receiving_chains = ChainStore::new();

            for chain in &pickle.receiver_chains {
                receiving_chains.push(chain.into())
            }

            for key in &pickle.message_keys {
                let ratchet_key =
                    RemoteRatchetKey::from(Curve25519PublicKey::from(key.ratchet_key));

                if let Some(receiving_chain) = receiving_chains.find_ratchet(&ratchet_key) {
                    receiving_chain.insert_message_key(key.into())
                }
            }

            if let Some(chain) = pickle.sender_chains.first() {
                // XXX: Passing in secret array as value.
                let ratchet_key = RatchetKey::from(Curve25519SecretKey::from_slice(
                    chain.secret_ratchet_key.as_ref(),
                ));
                let chain_key =
                    ChainKey::from_bytes_and_index(chain.chain_key.clone(), chain.chain_key_index);

                let root_key = RootKey::new(pickle.root_key.clone());

                let ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);
                let sending_ratchet = DoubleRatchet::from_ratchet_and_chain_key(ratchet, chain_key);

                Ok(Self {
                    session_keys: pickle.session_keys,
                    sending_ratchet,
                    receiving_chains,
                    config: SessionConfig::version_1(),
                })
            } else if let Some(chain) = receiving_chains.get(0) {
                let sending_ratchet = DoubleRatchet::inactive_from_libolm_pickle(
                    RemoteRootKey::new(pickle.root_key.clone()),
                    chain.ratchet_key(),
                );

                Ok(Self {
                    session_keys: pickle.session_keys,
                    sending_ratchet,
                    receiving_chains,
                    config: SessionConfig::version_1(),
                })
            } else {
                Err(crate::LibolmPickleError::InvalidSession)
            }
        }
    }
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`Session::pickle`].
#[derive(Deserialize, Serialize)]
pub struct SessionPickle {
    session_keys: SessionKeys,
    sending_ratchet: DoubleRatchet,
    receiving_chains: ChainStore,
    #[serde(default = "default_config")]
    config: SessionConfig,
}

const fn default_config() -> SessionConfig {
    SessionConfig::version_1()
}

impl SessionPickle {
    /// Serialize and encrypt the pickle using the given key.
    ///
    /// This is the inverse of [`SessionPickle::from_encrypted`].
    pub fn encrypt(self, pickle_key: &[u8; 32]) -> String {
        pickle(&self, pickle_key)
    }

    /// Obtain a pickle from a ciphertext by decrypting and deserializing using
    /// the given key.
    ///
    /// This is the inverse of [`SessionPickle::encrypt`].
    pub fn from_encrypted(ciphertext: &str, pickle_key: &[u8; 32]) -> Result<Self, PickleError> {
        unpickle(ciphertext, pickle_key)
    }
}

impl From<SessionPickle> for Session {
    fn from(pickle: SessionPickle) -> Self {
        Self {
            session_keys: pickle.session_keys,
            sending_ratchet: pickle.sending_ratchet,
            receiving_chains: pickle.receiving_chains,
            config: pickle.config,
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::{bail, Result};
    use assert_matches::assert_matches;
    use olm_rs::{
        account::OlmAccount,
        session::{OlmMessage, OlmSession},
    };

    use super::{DecryptionError, Session};
    use crate::{
        olm::{
            messages,
            session::receiver_chain::{MAX_MESSAGE_GAP, MAX_MESSAGE_KEYS},
            Account, SessionConfig, SessionPickle,
        },
        Curve25519PublicKey,
    };

    const PICKLE_KEY: [u8; 32] = [0u8; 32];

    /// Create a pair of accounts, one using vodozemac and one libolm.
    ///
    /// Then, create a pair of sessions between the two.
    pub fn session_and_libolm_pair() -> Result<(Account, OlmAccount, Session, OlmSession)> {
        let alice = Account::new();
        let bob = OlmAccount::new();
        bob.generate_one_time_keys(1);

        let one_time_key = bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .next()
            .cloned()
            .expect("Couldn't find a one-time key");

        let identity_keys = bob.parsed_identity_keys();
        let curve25519_key = Curve25519PublicKey::from_base64(identity_keys.curve25519())?;
        let one_time_key = Curve25519PublicKey::from_base64(&one_time_key)?;
        let mut alice_session =
            alice.create_outbound_session(SessionConfig::version_1(), curve25519_key, one_time_key);

        let message = "It's a secret to everybody";

        let olm_message = alice_session.encrypt(message);
        bob.mark_keys_as_published();

        if let OlmMessage::PreKey(m) = olm_message.into() {
            let session =
                bob.create_inbound_session_from(&alice.curve25519_key().to_base64(), m)?;

            Ok((alice, bob, alice_session, session))
        } else {
            bail!("Invalid message type");
        }
    }

    #[test]
    fn session_config() {
        let (_, _, alice_session, _) = session_and_libolm_pair().unwrap();
        assert_eq!(alice_session.session_config(), SessionConfig::version_1());
    }

    #[test]
    fn has_received_message() {
        let (_, _, mut alice_session, bob_session) = session_and_libolm_pair().unwrap();
        assert!(!alice_session.has_received_message());
        assert!(!bob_session.has_received_message());
        let message = bob_session.encrypt("Message").into();
        assert_eq!(
            "Message".as_bytes(),
            alice_session.decrypt(&message).expect("Should be able to decrypt message")
        );
        assert!(alice_session.has_received_message());
        assert!(!bob_session.has_received_message());
    }

    #[test]
    fn out_of_order_decryption() {
        let (_, _, mut alice_session, bob_session) = session_and_libolm_pair().unwrap();

        let message_1 = bob_session.encrypt("Message 1").into();
        let message_2 = bob_session.encrypt("Message 2").into();
        let message_3 = bob_session.encrypt("Message 3").into();

        assert_eq!(
            "Message 3".as_bytes(),
            alice_session.decrypt(&message_3).expect("Should be able to decrypt message 3")
        );
        assert_eq!(
            "Message 2".as_bytes(),
            alice_session.decrypt(&message_2).expect("Should be able to decrypt message 2")
        );
        assert_eq!(
            "Message 1".as_bytes(),
            alice_session.decrypt(&message_1).expect("Should be able to decrypt message 1")
        );
    }

    #[test]
    fn more_out_of_order_decryption() {
        let (_, _, mut alice_session, bob_session) = session_and_libolm_pair().unwrap();

        let message_1 = bob_session.encrypt("Message 1").into();
        let message_2 = bob_session.encrypt("Message 2").into();
        let message_3 = bob_session.encrypt("Message 3").into();

        assert_eq!(
            "Message 1".as_bytes(),
            alice_session.decrypt(&message_1).expect("Should be able to decrypt message 1")
        );

        assert_eq!(alice_session.receiving_chains.len(), 1);

        let message_4 = alice_session.encrypt("Message 4").into();
        assert_eq!(
            "Message 4",
            bob_session.decrypt(message_4).expect("Should be able to decrypt message 4")
        );

        let message_5 = bob_session.encrypt("Message 5").into();
        assert_eq!(
            "Message 5".as_bytes(),
            alice_session.decrypt(&message_5).expect("Should be able to decrypt message 5")
        );
        assert_eq!(
            "Message 3".as_bytes(),
            alice_session.decrypt(&message_3).expect("Should be able to decrypt message 3")
        );
        assert_eq!(
            "Message 2".as_bytes(),
            alice_session.decrypt(&message_2).expect("Should be able to decrypt message 2")
        );

        assert_eq!(alice_session.receiving_chains.len(), 2);
    }

    #[test]
    fn max_keys_out_of_order_decryption() {
        let (_, _, mut alice_session, bob_session) = session_and_libolm_pair().unwrap();

        let mut messages: Vec<messages::OlmMessage> = Vec::new();
        for i in 0..(MAX_MESSAGE_KEYS + 2) {
            messages.push(bob_session.encrypt(format!("Message {}", i).as_str()).into());
        }

        // Decrypt last message
        assert_eq!(
            format!("Message {}", MAX_MESSAGE_KEYS + 1).as_bytes(),
            alice_session
                .decrypt(&messages[MAX_MESSAGE_KEYS + 1])
                .expect("Should be able to decrypt last message")
        );

        // Cannot decrypt first message because it is more than MAX_MESSAGE_KEYS ago
        assert_matches!(
            alice_session.decrypt(&messages[0]),
            Err(DecryptionError::MissingMessageKey(_))
        );

        // Can decrypt all other messages
        for (i, message) in messages.iter().enumerate().skip(1).take(MAX_MESSAGE_KEYS) {
            assert_eq!(
                format!("Message {}", i).as_bytes(),
                alice_session
                    .decrypt(message)
                    .expect("Should be able to decrypt remaining messages")
            );
        }
    }

    #[test]
    fn max_gap_out_of_order_decryption() {
        let (_, _, mut alice_session, bob_session) = session_and_libolm_pair().unwrap();

        for i in 0..(MAX_MESSAGE_GAP + 1) {
            bob_session.encrypt(format!("Message {}", i).as_str());
        }

        let message = bob_session.encrypt("Message").into();
        assert_matches!(
            alice_session.decrypt(&message),
            Err(DecryptionError::TooBigMessageGap(_, _))
        );
    }

    #[test]
    fn pickle_default_config() {
        let json = r#"
            {
                "receiving_chains": {
                    "inner": []
                },
                "sending_ratchet": {
                    "active_ratchet": {
                        "ratchet_key": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                        "root_key": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
                    },
                    "parent_ratchet_key": null,
                    "ratchet_count": {
                        "Known": 1
                    },
                    "symmetric_key_ratchet": {
                        "index": 1,
                        "key": [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]
                    },
                    "type": "active"
                },
                "session_keys": {
                    "base_key": [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
                    "identity_key": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5],
                    "one_time_key": [6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6]
                }
            }
        "#;
        let pickle: SessionPickle =
            serde_json::from_str(json).expect("Should be able to deserialize JSON");
        assert_eq!(pickle.config, SessionConfig::version_1());
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn libolm_unpickling() {
        let (_, _, mut session, olm) = session_and_libolm_pair().unwrap();

        let plaintext = "It's a secret to everybody";
        let old_message = session.encrypt(plaintext);

        for _ in 0..9 {
            session.encrypt("Hello");
        }

        let message = session.encrypt("Hello");
        olm.decrypt(message.into()).expect("Should be able to decrypt message");

        let key = b"DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.to_vec() });

        let mut unpickled =
            Session::from_libolm_pickle(&pickle, key).expect("Should be able to unpickle session");

        assert_eq!(olm.session_id(), unpickled.session_id());

        assert_eq!(
            unpickled
                .decrypt(&old_message)
                .expect("Should be able to decrypt old message with unpickled session"),
            plaintext.as_bytes()
        );

        let message = unpickled.encrypt(plaintext);

        assert_eq!(
            session.decrypt(&message).expect("Should be able to decrypt re-encrypted message"),
            plaintext.as_bytes()
        );
    }

    #[test]
    fn session_pickling_roundtrip_is_identity() {
        let (_, _, session, _) = session_and_libolm_pair().unwrap();

        let pickle = session.pickle().encrypt(&PICKLE_KEY);

        let decrypted_pickle = SessionPickle::from_encrypted(&pickle, &PICKLE_KEY)
            .expect("Should be able to decrypt encrypted pickle");
        let unpickled_group_session = Session::from_pickle(decrypted_pickle);
        let repickle = unpickled_group_session.pickle();

        assert_eq!(session.session_id(), unpickled_group_session.session_id());

        let decrypted_pickle = SessionPickle::from_encrypted(&pickle, &PICKLE_KEY)
            .expect("Should be able to decrypt encrypted pickle");
        let pickle = serde_json::to_value(decrypted_pickle).unwrap();
        let repickle = serde_json::to_value(repickle).unwrap();

        assert_eq!(pickle, repickle);
    }
}
