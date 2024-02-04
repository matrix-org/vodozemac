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
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use self::ratchet::RatchetKey;
use super::{
    session_config::{SessionCreator, Version},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    AnyMessage, AnyNormalMessage, InterolmPreKeyMessage, SessionConfig,
};
#[cfg(feature = "low-level-api")]
use crate::hazmat::olm::MessageKey;
use crate::{
    olm::{
        messages::{AnyInterolmMessage, AnyNativeMessage, PreKeyMessage},
        session::root_key::{RemoteRootKey, RootKey},
    },
    types::Curve25519SecretKey,
    utilities::{pickle, unpickle},
    Curve25519PublicKey, PickleError,
};

const MAX_RECEIVING_CHAINS: usize = 5;

/// Error type for decryption failures.
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// The message authentication code of the message was invalid.
    #[error("Failed decrypting message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),
    /// The length of the message authentication code of the message did not
    /// match our expected length.
    #[error("Failed decrypting message, invalid MAC length: expected {0}, got {1}")]
    InvalidMACLength(usize, usize),
    /// The ciphertext of the message isn't padded correctly.
    #[error("Failed decrypting message, invalid padding")]
    InvalidPadding(#[from] UnpadError),
    /// The session is missing the correct message key to decrypt the message,
    /// either because it was already used up, or because the Session has been
    /// ratcheted forwards and the message key has been discarded.
    #[error("The message key with the given key can't be created, message index: {0}")]
    MissingMessageKey(u64),
    /// Too many messages have been skipped to attempt decrypting this message.
    #[error("The message gap was too big, got {0}, max allowed {1}")]
    TooBigMessageGap(u64, u64),
    /// We were expecting one algorithm but the message was in another.
    #[error("The message had an unexpected algorithm: expected {0}, got {1}")]
    WrongAlgorithm(String, String),
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

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[cfg(feature = "libolm-compat")]
    pub fn get(&self, index: usize) -> Option<&ReceiverChain> {
        self.inner.get(index)
    }

    fn find_ratchet(&mut self, ratchet_key: &RemoteRatchetKey) -> Option<&mut ReceiverChain> {
        self.inner.iter_mut().find(|r| r.belongs_to(ratchet_key))
    }

    #[cfg(feature = "interolm")]
    fn previous_chain(&self) -> Option<ReceiverChain> {
        let num_chains = self.inner.len();

        if num_chains >= 2 {
            self.inner.get(num_chains - 2).cloned()
        } else {
            None
        }
    }

    #[cfg(feature = "interolm")]
    fn previous_counter(&self) -> u32 {
        match self.previous_chain() {
            Some(chain) => {
                if chain.hkdf_ratchet.chain_index() > 0 {
                    (chain.hkdf_ratchet.chain_index() - 1)
                        .try_into()
                        .expect("Interolm counter should fit into u32")
                } else {
                    0
                }
            }
            None => 0,
        }
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
///   send a message in
/// this channel, or
/// - [`Account::create_inbound_session`], if the other participant initiated
///   the channel by
/// sending you a message.
///
/// [`Account`]: crate::olm::Account
/// [`Account::create_outbound_session`]: crate::olm::Account::create_outbound_session
/// [`Account::create_inbound_session`]: crate::olm::Account::create_inbound_session
pub struct Session {
    session_keys: SessionKeys,
    sending_ratchet: DoubleRatchet,
    receiving_chains: ChainStore,
    config: SessionConfig,
    session_creator: SessionCreator,
}

impl Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { session_keys: _, sending_ratchet, receiving_chains, config, session_creator } =
            self;

        f.debug_struct("Session")
            .field("session_id", &self.session_id())
            .field("sending_chain_index", &sending_ratchet.chain_index())
            .field("receiving_chains", &receiving_chains.inner)
            .field("message_received", &self.has_received_message())
            .field("session_creator", session_creator)
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
        let local_ratchet = DoubleRatchet::active(&config, shared_secret);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_chains: Default::default(),
            config,
            session_creator: SessionCreator::Us,
        }
    }

    pub(super) fn new_remote(
        config: &SessionConfig,
        shared_secret: RemoteShared3DHSecret,
        remote_ratchet_key: Curve25519PublicKey,
        session_keys: SessionKeys,
    ) -> Self {
        let (root_key, remote_chain_key) = shared_secret.expand(config);

        let remote_ratchet_key = RemoteRatchetKey::from(remote_ratchet_key);
        let root_key = RemoteRootKey::new(root_key);
        let remote_chain_key = RemoteChainKey::new(remote_chain_key);

        let local_ratchet = DoubleRatchet::inactive(root_key, remote_ratchet_key);
        let remote_ratchet = ReceiverChain::new(remote_ratchet_key, remote_chain_key);

        let mut ratchet_store = ChainStore::new();
        ratchet_store.push(remote_ratchet);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_chains: ratchet_store,
            config: *config,
            session_creator: SessionCreator::Them,
        }
    }

    #[cfg(feature = "interolm")]
    pub(super) fn new_interolm(
        config: SessionConfig,
        shared_secret: Shared3DHSecret,
        session_keys: SessionKeys,
    ) -> Self {
        let their_ratchet_key = RemoteRatchetKey(session_keys.signed_pre_key);

        let (local_ratchet, receiver_chain) =
            DoubleRatchet::active_interolm(&config, shared_secret, their_ratchet_key);

        let mut ratchet_store = ChainStore::new();
        ratchet_store.push(receiver_chain);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_chains: ratchet_store,
            config,
            session_creator: SessionCreator::Us,
        }
    }

    #[cfg(feature = "interolm")]
    pub(super) fn new_interolm_remote(
        config: &SessionConfig,
        shared_secret: RemoteShared3DHSecret,
        remote_ratchet_key: RemoteRatchetKey,
        session_keys: SessionKeys,
        our_ratchet_key: RatchetKey,
    ) -> Self {
        let (local_ratchet, receiver_chain) = DoubleRatchet::inactive_interolm(
            config,
            shared_secret,
            our_ratchet_key,
            remote_ratchet_key,
        );

        let mut ratchet_store = ChainStore::new();
        ratchet_store.push(receiver_chain);

        Self {
            session_keys,
            sending_ratchet: local_ratchet,
            receiving_chains: ratchet_store,
            config: *config,
            session_creator: SessionCreator::Them,
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
    pub fn has_received_message(&self) -> bool {
        let initial_ratchet_key = RemoteRatchetKey(self.session_keys().signed_pre_key);

        // Interolm immediately initializes a receiving chain, using the signed prekey
        // as the initial (remote) ratchet key, even though it's never received a
        // message from the other side. Therefore we need to filter that chain
        // out when trying to determine whether we've ever received a message
        // from the other side.
        self.receiving_chains.inner.iter().any(|c| !c.belongs_to(&initial_ratchet_key))
    }

    pub fn is_message_for_this_session(&self, message: &AnyMessage) -> Option<bool> {
        match message {
            AnyMessage::Native(AnyNativeMessage::PreKey(n)) => {
                Some(n.session_id() == self.session_id())
            }
            AnyMessage::Interolm(AnyInterolmMessage::PreKey(s)) => {
                if let Version::Interolm(meta_data) = self.config.version {
                    let pre_key_id = meta_data
                        .one_time_key_id
                        .map(|k| k.0.try_into().expect("Interolm key IDs are bound to 32 bits"));
                    let signed_pre_key_id: u32 = meta_data
                        .signed_pre_key_id
                        .0
                        .try_into()
                        .expect("Interolm key IDs are bound to 32 bits");

                    Some(
                        pre_key_id == s.pre_key_id
                            && signed_pre_key_id == s.signed_pre_key_id
                            && meta_data.registration_id == s.registration_id,
                    )
                } else {
                    Some(false)
                }
            }
            _ => None,
        }
    }

    /// Encrypt the `plaintext` and construct an [`AnyNativeMessage`].
    ///
    /// The message will either be a pre-key message or a normal message,
    /// depending on whether the session is fully established. A session is
    /// fully established once you receive (and decrypt) at least one
    /// message from the other side.
    pub fn encrypt(&mut self, plaintext: impl AsRef<[u8]>) -> AnyNativeMessage {
        let message = match self.config.version {
            Version::V1 => {
                self.sending_ratchet.encrypt_truncated_mac(&self.config, plaintext.as_ref())
            }
            Version::V2 => self.sending_ratchet.encrypt(&self.config, plaintext.as_ref()),
            #[cfg(feature = "interolm")]
            Version::Interolm(..) => panic!("`Session::encrypt` called on an Interolm session!"),
        };

        if self.has_received_message() {
            AnyNativeMessage::Normal(message)
        } else {
            let message = PreKeyMessage::new(self.session_keys.into(), message);

            AnyNativeMessage::PreKey(message)
        }
    }

    /// Encrypt the `plaintext` for Interolm and construct an
    /// [`AnyInterolmMessage`].
    ///
    /// The message will either be a pre-key message or a normal message,
    /// depending on whether the session is fully established. A session is
    /// fully established once you receive (and decrypt) at least one
    /// message from the other side.
    #[cfg(feature = "interolm")]
    pub fn encrypt_interolm(&mut self, plaintext: impl AsRef<[u8]>) -> AnyInterolmMessage {
        let (metadata, message) = match self.config.version {
            Version::V1 | Version::V2 => {
                panic!("`Session::encrypt_interolm` called on a non-Interolm session!")
            }
            Version::Interolm(metadata) => (
                metadata,
                self.sending_ratchet.encrypt_interolm(
                    &self.config,
                    self.session_creator,
                    &self.session_keys,
                    self.receiving_chains.previous_counter(),
                    plaintext.as_ref(),
                ),
            ),
        };

        if self.has_received_message() {
            AnyInterolmMessage::Normal(message)
        } else {
            let message = InterolmPreKeyMessage::new(self.session_keys, metadata, message);

            AnyInterolmMessage::PreKey(message)
        }
    }

    /// Get the keys associated with this session.
    pub fn session_keys(&self) -> SessionKeys {
        self.session_keys
    }

    pub fn session_config(&self) -> SessionConfig {
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
    pub fn decrypt(&mut self, message: &AnyNativeMessage) -> Result<Vec<u8>, DecryptionError> {
        let decrypted = match message {
            AnyNativeMessage::Normal(m) => self.decrypt_decoded(AnyNormalMessage::Native(m))?,
            AnyNativeMessage::PreKey(m) => {
                self.decrypt_decoded(AnyNormalMessage::Native(&m.message))?
            }
        };

        Ok(decrypted)
    }

    /// Try to decrypt an Interolm message, which will either return the
    /// plaintext or result in a [`DecryptionError`].
    ///
    /// [`DecryptionError`]: self::DecryptionError
    #[cfg(feature = "interolm")]
    pub fn decrypt_interolm(
        &mut self,
        message: &AnyInterolmMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        let decrypted = match message {
            AnyInterolmMessage::Normal(m) => self.decrypt_decoded(AnyNormalMessage::Interolm(m))?,
            AnyInterolmMessage::PreKey(m) => {
                self.decrypt_decoded(AnyNormalMessage::Interolm(&m.message))?
            }
        };

        Ok(decrypted)
    }

    pub(super) fn decrypt_decoded(
        &mut self,
        message: AnyNormalMessage<'_>,
    ) -> Result<Vec<u8>, DecryptionError> {
        let ratchet_key = RemoteRatchetKey::from(message.ratchet_key());

        if let Some(ratchet) = self.receiving_chains.find_ratchet(&ratchet_key) {
            ratchet.decrypt(&self.config, &self.session_keys, self.session_creator, message)
        } else {
            let (sending_ratchet, mut remote_ratchet) =
                self.sending_ratchet.advance(&self.config, ratchet_key);

            let plaintext = remote_ratchet.decrypt(
                &self.config,
                &self.session_keys,
                self.session_creator,
                message,
            )?;

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
            session_creator: self.session_creator,
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
        use chain_key::ChainKey;
        use matrix_pickle::Decode;
        use message_key::RemoteMessageKey;

        use crate::{olm::session::ratchet::Ratchet, utilities::unpickle_libolm};

        #[derive(Debug, Decode, Zeroize)]
        #[zeroize(drop)]
        struct SenderChain {
            public_ratchet_key: [u8; 32],
            #[secret]
            secret_ratchet_key: Box<[u8; 32]>,
            chain_key: Box<[u8; 32]>,
            chain_key_index: u32,
        }

        #[derive(Debug, Decode, Zeroize)]
        #[zeroize(drop)]
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

                ReceiverChain::new(ratchet_key, chain_key)
            }
        }

        #[derive(Debug, Decode, Zeroize)]
        #[zeroize(drop)]
        struct MessageKey {
            ratchet_key: [u8; 32],
            #[secret]
            message_key: Box<[u8; 32]>,
            index: u32,
        }

        /// The set of keys that were used to establish the Olm Session.
        // XXX: Could probably be removed (in favour of) when SessionKeysWire is renamed to
        // OlmSessionKeys.
        #[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Decode)]
        pub struct OlmSessionKeys {
            /// Alice's identity key.
            pub identity_key: Curve25519PublicKey,
            /// Alice's ephemeral (base) key.
            pub base_key: Curve25519PublicKey,
            /// Bob's OTK which Alice used.
            pub one_time_key: Curve25519PublicKey,
        }

        impl From<&MessageKey> for RemoteMessageKey {
            fn from(key: &MessageKey) -> Self {
                RemoteMessageKey { key: key.message_key.clone(), index: key.index.into() }
            }
        }

        #[derive(Decode)]
        struct Pickle {
            #[allow(dead_code)]
            version: u32,
            #[allow(dead_code)]
            received_message: bool,
            session_keys: OlmSessionKeys,
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

            #[allow(unreachable_code, clippy::diverging_sub_expression)]
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

                let _session_keys = SessionKeys {
                    identity_key: pickle.session_keys.identity_key,
                    base_key: pickle.session_keys.base_key,
                    signed_pre_key: pickle.session_keys.one_time_key,
                    one_time_key: None,
                    // TODO: Figure out what to do with libolm session pickles
                    other_identity_key: unimplemented!(
                        "libolm session pickles don't contain this information, \
                        so there's not enough information to reconstruct a `Session`"
                    ),
                };

                if let Some(chain) = pickle.sender_chains.first() {
                    // XXX: Passing in secret array as value.
                    let ratchet_key = RatchetKey::from(Curve25519SecretKey::from_slice(
                        chain.secret_ratchet_key.as_ref(),
                    ));
                    let chain_key = ChainKey::from_bytes_and_index(
                        chain.chain_key.clone(),
                        chain.chain_key_index,
                    );

                    let root_key = RootKey::new(pickle.root_key.clone());

                    let ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);
                    let sending_ratchet =
                        DoubleRatchet::from_ratchet_and_chain_key(ratchet, chain_key);

                    Ok(Self {
                        session_keys: _session_keys,
                        sending_ratchet,
                        receiving_chains,
                        config: SessionConfig::version_1(),
                        session_creator: todo!("libolm session pickles don't contain this information, \
                                              so there's not enough information to reconstruct a `Session`")
                    })
                } else if let Some(chain) = receiving_chains.get(0) {
                    let sending_ratchet = DoubleRatchet::inactive(
                        RemoteRootKey::new(pickle.root_key.clone()),
                        chain.ratchet_key(),
                    );

                    Ok(Self {
                        session_keys: _session_keys,
                        sending_ratchet,
                        receiving_chains,
                        config: SessionConfig::version_1(),
                        session_creator: todo!("libolm session pickles don't contain this information, \
                                              so there's not enough information to reconstruct a `Session`")
                    })
                } else {
                    Err(crate::LibolmPickleError::InvalidSession)
                }
            }
        }

        const PICKLE_VERSION: u32 = 1;
        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
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
    session_creator: SessionCreator,
}

fn default_config() -> SessionConfig {
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
            session_creator: pickle.session_creator,
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::{bail, Result};
    use olm_rs::{
        account::OlmAccount,
        session::{OlmMessage, OlmSession},
    };

    use super::Session;
    use crate::{
        olm::{
            Account, AnyInterolmMessage, AnyMessage, InboundCreationResult, SessionConfig,
            SessionPickle,
        },
        Curve25519PublicKey, KeyId,
    };

    const PICKLE_KEY: [u8; 32] = [0u8; 32];

    fn sessions() -> Result<(Account, OlmAccount, Session, OlmSession)> {
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
        let mut alice_session = alice.create_outbound_session(
            SessionConfig::version_1(),
            curve25519_key,
            one_time_key,
            None,
        );

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

    fn interolm_sessions() -> Result<(Account, Account, Session, Session)> {
        let alice = Account::new();
        let mut bob = Account::new();
        bob.generate_one_time_keys(2);

        let mut bob_prekeys: Vec<(KeyId, Curve25519PublicKey)> =
            bob.one_time_keys().iter().map(|(t1, t2)| (*t1, *t2)).take(2).collect();
        let (otk_id, otk) =
            bob_prekeys.pop().expect("Bob should have an OTK because we just generated it");
        let (skey_id, skey) = bob_prekeys
            .pop()
            .expect("Bob should have a signed prekey because we just generated it");

        bob.mark_keys_as_published();

        let identity_keys = bob.identity_keys();
        let curve25519_key = identity_keys.curve25519;

        let mut alice_session = alice.create_outbound_session(
            SessionConfig::version_interolm(0, skey_id, Some(otk_id)),
            curve25519_key,
            skey,
            Some(otk),
        );

        let message = "It's a secret to everybody";
        let ciphertext = alice_session.encrypt_interolm(message);

        if let AnyMessage::Interolm(AnyInterolmMessage::PreKey(m)) = ciphertext.into() {
            let InboundCreationResult { session, .. } =
                bob.create_inbound_session(alice.identity_keys().curve25519, &m.into())?;

            Ok((alice, bob, alice_session, session))
        } else {
            bail!("Invalid message type");
        }
    }

    #[test]
    fn out_of_order_decryption() -> Result<()> {
        let (_, _, mut alice_session, bob_session) = sessions()?;

        let message_1 = bob_session.encrypt("Message 1").into();
        let message_2 = bob_session.encrypt("Message 2").into();
        let message_3 = bob_session.encrypt("Message 3").into();

        assert_eq!("Message 3".as_bytes(), alice_session.decrypt(&message_3)?);
        assert_eq!("Message 2".as_bytes(), alice_session.decrypt(&message_2)?);
        assert_eq!("Message 1".as_bytes(), alice_session.decrypt(&message_1)?);

        Ok(())
    }

    #[test]
    fn more_out_of_order_decryption() -> Result<()> {
        let (_, _, mut alice_session, bob_session) = sessions()?;

        let message_1 = bob_session.encrypt("Message 1").into();
        let message_2 = bob_session.encrypt("Message 2").into();
        let message_3 = bob_session.encrypt("Message 3").into();

        assert_eq!("Message 1".as_bytes(), alice_session.decrypt(&message_1)?);

        assert_eq!(alice_session.receiving_chains.len(), 1);

        let message_4 = alice_session.encrypt("Message 4").into();
        assert_eq!("Message 4", bob_session.decrypt(message_4)?);

        let message_5 = bob_session.encrypt("Message 5").into();
        assert_eq!("Message 5".as_bytes(), alice_session.decrypt(&message_5)?);
        assert_eq!("Message 3".as_bytes(), alice_session.decrypt(&message_3)?);
        assert_eq!("Message 2".as_bytes(), alice_session.decrypt(&message_2)?);

        assert_eq!(alice_session.receiving_chains.len(), 2);

        Ok(())
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn libolm_unpickling() -> Result<()> {
        let (_, _, mut session, olm) = sessions()?;

        let plaintext = "It's a secret to everybody";
        let old_message = session.encrypt(plaintext);

        for _ in 0..9 {
            session.encrypt("Hello");
        }

        let message = session.encrypt("Hello");
        olm.decrypt(message.into())?;

        let key = b"DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.to_vec() });

        let mut unpickled = Session::from_libolm_pickle(&pickle, key)?;

        assert_eq!(olm.session_id(), unpickled.session_id());

        assert_eq!(unpickled.decrypt(&old_message)?, plaintext.as_bytes());

        let message = unpickled.encrypt(plaintext);

        assert_eq!(session.decrypt(&message)?, plaintext.as_bytes());

        Ok(())
    }

    #[test]
    fn session_pickling_roundtrip_is_identity() -> Result<()> {
        let (_, _, session, _) = sessions()?;

        let pickle = session.pickle().encrypt(&PICKLE_KEY);

        let decrypted_pickle = SessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let unpickled_group_session = Session::from_pickle(decrypted_pickle);
        let repickle = unpickled_group_session.pickle();

        assert_eq!(session.session_id(), unpickled_group_session.session_id());

        let decrypted_pickle = SessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let pickle = serde_json::to_value(decrypted_pickle)?;
        let repickle = serde_json::to_value(repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    fn message_received_flag_survives_pickling_roundtrip() -> Result<()> {
        let (_, _, alice_session, mut bob_session) = interolm_sessions()?;

        assert!(!alice_session.has_received_message());

        let pickle = alice_session.pickle().encrypt(&PICKLE_KEY);
        let decrypted_pickle = SessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let mut alice_session = Session::from_pickle(decrypted_pickle);

        assert!(!alice_session.has_received_message());

        let bob_msg = bob_session.encrypt_interolm("Hello Alice!");
        let _ = alice_session
            .decrypt_interolm(&bob_msg)
            .expect("Alice should be able to decrypt Bob's message");

        assert!(alice_session.has_received_message());

        let pickle = alice_session.pickle().encrypt(&PICKLE_KEY);
        let decrypted_pickle = SessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let alice_session = Session::from_pickle(decrypted_pickle);

        assert!(alice_session.has_received_message());

        Ok(())
    }
}
