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
mod message_key;
mod ratchet;
mod receiver_chain;
mod root_key;

use std::ops::Deref;

use arrayvec::ArrayVec;
use block_modes::BlockModeError;
use chain_key::RemoteChainKey;
use double_ratchet::DoubleRatchet;
use hmac::digest::MacError;
use ratchet::RemoteRatchetKey;
use receiver_chain::ReceiverChain;
use root_key::RemoteRootKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use self::double_ratchet::DoubleRatchetPickle;
use super::{
    session_keys::{SessionKeys, SessionKeysPickle},
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
};
use crate::{
    olm::messages::{DecodedMessage, EncodedPrekeyMessage, Message, OlmMessage, PreKeyMessage},
    utilities::base64_encode,
    Curve25519PublicKey, DecodeError,
};

const MAX_RECEIVING_CHAINS: usize = 5;

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

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get(&self, index: usize) -> Option<&ReceiverChain> {
        self.inner.get(index)
    }

    fn find_ratchet(&mut self, ratchet_key: &RemoteRatchetKey) -> Option<&mut ReceiverChain> {
        self.inner.iter_mut().find(|r| r.belongs_to(ratchet_key))
    }
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("The message wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Failed decrypting Olm message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),
    #[error("Failed decrypting Olm message, invalid ciphertext: {0}")]
    InvalidCiphertext(#[from] BlockModeError),
    #[error("The message key with the given key can't be created, message index: {0}")]
    MissingMessageKey(u64),
    #[error("The message gap was too big, got {0}, max allowed {}")]
    TooBigMessageGap(u64, u64),
    #[error("The message couldn't be decoded: {0}")]
    DecodeError(#[from] DecodeError),
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
/// introduces new entropy into    the channel as messages are sent and
/// received. This imbues the channel with *self-healing*    properties,
/// allowing it to recover from a momentary loss of confidentiality in the event
/// of    a key compromise.
/// 2. They are *asynchronous*, allowing the participant to start sending
/// messages to the other    side even if the other participant is not online at
/// the moment.
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
#[derive(Deserialize)]
#[serde(from = "SessionPickle")]
pub struct Session {
    session_keys: SessionKeys,
    sending_ratchet: DoubleRatchet,
    receiving_chains: ChainStore,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("session_id", &self.session_id()).finish_non_exhaustive()
    }
}

impl Session {
    pub(super) fn new(shared_secret: Shared3DHSecret, session_keys: SessionKeys) -> Self {
        let local_ratchet = DoubleRatchet::active(shared_secret);

        Self { session_keys, sending_ratchet: local_ratchet, receiving_chains: Default::default() }
    }

    pub(super) fn new_remote(
        shared_secret: RemoteShared3DHSecret,
        remote_ratchet_key: Curve25519PublicKey,
        session_keys: SessionKeys,
    ) -> Self {
        let (root_key, remote_chain_key) = shared_secret.expand();

        let remote_ratchet_key = RemoteRatchetKey::from(remote_ratchet_key);
        let root_key = RemoteRootKey::new(root_key);
        let remote_chain_key = RemoteChainKey::new(remote_chain_key);

        let local_ratchet = DoubleRatchet::inactive(root_key, remote_ratchet_key);
        let remote_ratchet = ReceiverChain::new(remote_ratchet_key, remote_chain_key);

        let mut ratchet_store = ChainStore::new();
        ratchet_store.push(remote_ratchet);

        Self { session_keys, sending_ratchet: local_ratchet, receiving_chains: ratchet_store }
    }

    /// Returns the globally unique session ID, in base64-encoded form.
    ///
    /// A session ID is the SHA256 of the concatenation of the account's
    /// identity key, an ephemeral base key and the one-time key which was
    /// used to establish the session. Due to the construction, every
    /// session ID is (probabilistically) globally unique.
    pub fn session_id(&self) -> String {
        let sha = Sha256::new();

        let digest = sha
            .chain_update(self.session_keys.identity_key.as_bytes())
            .chain_update(self.session_keys.base_key.as_bytes())
            .chain_update(self.session_keys.one_time_key.as_bytes())
            .finalize();

        base64_encode(digest)
    }

    // Have we ever received and decrypted a message from the other side?
    fn has_received_message(&self) -> bool {
        !self.receiving_chains.is_empty()
    }

    /// Encrypt the `plaintext` and construct an [`OlmMessage`].
    ///
    /// The message will either be a pre-key message or a normal message,
    /// depending on whether the session is fully established. A session is
    /// fully established once you receive (and decrypt) at least one
    /// message from the other side.
    pub fn encrypt(&mut self, plaintext: &str) -> OlmMessage {
        let message = self.sending_ratchet.encrypt(plaintext);

        if self.has_received_message() {
            OlmMessage::Normal(Message { inner: base64_encode(message) })
        } else {
            let message = EncodedPrekeyMessage::new(
                &self.session_keys.one_time_key,
                &self.session_keys.base_key,
                &self.session_keys.identity_key,
                message,
            );

            OlmMessage::PreKey(PreKeyMessage { inner: base64_encode(message) })
        }
    }

    /// Try to decrypt an Olm message, which will either return the plaintext or
    /// result in a [`DecryptionError`].
    ///
    /// [`DecryptionError`]: self::DecryptionError
    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String, DecryptionError> {
        let decrypted = match message {
            OlmMessage::Normal(m) => {
                let message = m.decode()?;
                self.decrypt_decoded(message)?
            }
            OlmMessage::PreKey(m) => {
                let message = m.decode()?;
                self.decrypt_decoded(message.message)?
            }
        };

        Ok(String::from_utf8_lossy(&decrypted).to_string())
    }

    pub(super) fn decrypt_decoded(
        &mut self,
        message: DecodedMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        let ratchet_key = RemoteRatchetKey::from(message.ratchet_key);

        if let Some(ratchet) = self.receiving_chains.find_ratchet(&ratchet_key) {
            Ok(ratchet.decrypt(&message)?)
        } else {
            let (sending_ratchet, mut remote_ratchet) = self.sending_ratchet.advance(ratchet_key);

            let plaintext = remote_ratchet.decrypt(&message)?;

            self.sending_ratchet = sending_ratchet;
            self.receiving_chains.push(remote_ratchet);

            Ok(plaintext)
        }
    }

    /// Convert the session into a struct which implements [`serde::Serialize`]
    /// and [`serde::Deserialize`].
    pub fn pickle(&self) -> SessionPickle {
        let session_keys: SessionKeysPickle = self.session_keys.clone();
        SessionPickle {
            session_keys,
            sending_ratchet: self.sending_ratchet.clone(),
            receiving_chains: self.receiving_chains.clone(),
        }
    }

    /// Pickle the session and serialize it to a JSON string.
    ///
    /// The string is wrapped in [`SessionPickledJSON`] which can be derefed to
    /// access the content as a string slice. The string will zeroize itself
    /// when it drops to prevent secrets contained inside from lingering in
    /// memory.
    ///
    /// [`SessionPickledJSON`]: self::SessionPickledJSON
    pub fn pickle_to_json_string(&self) -> SessionPickledJSON {
        let pickle: SessionPickle = self.pickle();
        SessionPickledJSON(
            serde_json::to_string_pretty(&pickle).expect("Session serialization failed."),
        )
    }

    /// Create a [`Session`] object by unpickling a session pickle in libolm
    /// legacy pickle format.
    ///
    /// Such pickles are encrypted and need to first be decrypted using
    /// `pickle_key`.
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &str,
    ) -> Result<Self, crate::LibolmUnpickleError> {
        use chain_key::ChainKey;
        use message_key::RemoteMessageKey;
        use ratchet::{Ratchet, RatchetKey};
        use root_key::RootKey;

        use crate::{
            types::Curve25519SecretKey,
            utilities::{unpickle_libolm, Decode},
        };

        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        struct SenderChain {
            public_ratchet_key: [u8; 32],
            secret_ratchet_key: [u8; 32],
            chain_key: [u8; 32],
            chain_key_index: u32,
        }

        impl Decode for SenderChain {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Self {
                    public_ratchet_key: <[u8; 32]>::decode(reader)?,
                    secret_ratchet_key: <[u8; 32]>::decode(reader)?,
                    chain_key: <[u8; 32]>::decode(reader)?,
                    chain_key_index: u32::decode(reader)?,
                })
            }
        }

        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        struct ReceivingChain {
            ratchet_key: [u8; 32],
            chain_key: [u8; 32],
            chain_key_index: u32,
        }

        impl Decode for ReceivingChain {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Self {
                    ratchet_key: <[u8; 32]>::decode(reader)?,
                    chain_key: <[u8; 32]>::decode(reader)?,
                    chain_key_index: u32::decode(reader)?,
                })
            }
        }

        impl From<&ReceivingChain> for ReceiverChain {
            fn from(chain: &ReceivingChain) -> Self {
                let ratchet_key = RemoteRatchetKey::from(chain.ratchet_key);
                let chain_key =
                    RemoteChainKey::from_bytes_and_index(chain.chain_key, chain.chain_key_index);

                ReceiverChain::new(ratchet_key, chain_key)
            }
        }

        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        struct MessageKey {
            ratchet_key: [u8; 32],
            message_key: [u8; 32],
            index: u32,
        }

        impl Decode for MessageKey {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Self {
                    ratchet_key: <[u8; 32]>::decode(reader)?,
                    message_key: <[u8; 32]>::decode(reader)?,
                    index: u32::decode(reader)?,
                })
            }
        }

        impl From<&MessageKey> for RemoteMessageKey {
            fn from(key: &MessageKey) -> Self {
                RemoteMessageKey { key: key.message_key, index: key.index.into() }
            }
        }

        struct Pickle {
            #[allow(dead_code)]
            version: u32,
            #[allow(dead_code)]
            received_message: bool,
            session_keys: SessionKeys,
            root_key: [u8; 32],
            sender_chains: Vec<SenderChain>,
            receiver_chains: Vec<ReceivingChain>,
            message_keys: Vec<MessageKey>,
        }

        impl Decode for Pickle {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Self {
                    version: u32::decode(reader)?,
                    received_message: bool::decode(reader)?,
                    session_keys: SessionKeys::decode(reader)?,
                    root_key: <[u8; 32]>::decode(reader)?,
                    sender_chains: Vec::decode(reader)?,
                    receiver_chains: Vec::decode(reader)?,
                    message_keys: Vec::decode(reader)?,
                })
            }
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
            type Error = crate::LibolmUnpickleError;

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

                if let Some(chain) = pickle.sender_chains.get(0) {
                    let ratchet_key =
                        RatchetKey::from(Curve25519SecretKey::from(chain.secret_ratchet_key));
                    let chain_key =
                        ChainKey::from_bytes_and_index(chain.chain_key, chain.chain_key_index);

                    let root_key = RootKey::new(pickle.root_key);

                    let ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);
                    let sending_ratchet =
                        DoubleRatchet::from_ratchet_and_chain_key(ratchet, chain_key);

                    Ok(Self {
                        session_keys: pickle.session_keys.clone(),
                        sending_ratchet,
                        receiving_chains,
                    })
                } else if let Some(chain) = receiving_chains.get(0) {
                    let sending_ratchet = DoubleRatchet::inactive(
                        RemoteRootKey::new(pickle.root_key),
                        chain.ratchet_key(),
                    );

                    Ok(Self {
                        session_keys: pickle.session_keys.clone(),
                        sending_ratchet,
                        receiving_chains,
                    })
                } else {
                    Err(crate::LibolmUnpickleError::InvalidSession)
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
    session_keys: SessionKeysPickle,
    sending_ratchet: DoubleRatchetPickle,
    receiving_chains: ChainStorePickle,
}

impl SessionPickle {
    /// Convert the pickle format back into a [`Session`].
    pub fn unpickle(self) -> Session {
        self.into()
    }
}

impl From<SessionPickle> for Session {
    fn from(pickle: SessionPickle) -> Self {
        Self {
            session_keys: pickle.session_keys,
            sending_ratchet: pickle.sending_ratchet,
            receiving_chains: pickle.receiving_chains,
        }
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct SessionPickledJSON(String);

impl SessionPickledJSON {
    /// Access the serialized content as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Try to convert the serialized JSON string back into a [`Session`].
    pub fn unpickle(self) -> Result<Session, SessionUnpicklingError> {
        let pickle: SessionPickle = serde_json::from_str(&self.0)?;
        Ok(pickle.unpickle())
    }
}

impl AsRef<str> for SessionPickledJSON {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for SessionPickledJSON {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[derive(Error, Debug)]
pub enum SessionUnpicklingError {
    #[error("Pickle format corrupted: {0}")]
    CorruptedPickle(#[from] serde_json::error::Error),
}

type ChainStorePickle = ChainStore;

#[cfg(test)]
mod test {
    use anyhow::{bail, Result};
    use olm_rs::{
        account::OlmAccount,
        session::{OlmMessage, OlmSession},
        PicklingMode,
    };

    use super::Session;
    use crate::{olm::Account, Curve25519PublicKey};

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
        let mut alice_session = alice.create_outbound_session(curve25519_key, one_time_key);

        let message = "It's a secret to everybody";

        let olm_message: OlmMessage = alice_session.encrypt(message).into();
        bob.mark_keys_as_published();

        if let OlmMessage::PreKey(m) = olm_message {
            let session = bob.create_inbound_session_from(alice.curve25519_key_encoded(), m)?;

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

        assert_eq!("Message 3", alice_session.decrypt(&message_3)?);
        assert_eq!("Message 2", alice_session.decrypt(&message_2)?);
        assert_eq!("Message 1", alice_session.decrypt(&message_1)?);

        Ok(())
    }

    #[test]
    fn more_out_of_order_decryption() -> Result<()> {
        let (_, _, mut alice_session, bob_session) = sessions()?;

        let message_1 = bob_session.encrypt("Message 1").into();
        let message_2 = bob_session.encrypt("Message 2").into();
        let message_3 = bob_session.encrypt("Message 3").into();

        assert_eq!("Message 1", alice_session.decrypt(&message_1)?);

        assert_eq!(alice_session.receiving_chains.len(), 1);

        let message_4 = alice_session.encrypt("Message 4").into();
        assert_eq!("Message 4", bob_session.decrypt(message_4)?);

        let message_5 = bob_session.encrypt("Message 5").into();
        assert_eq!("Message 5", alice_session.decrypt(&message_5)?);
        assert_eq!("Message 3", alice_session.decrypt(&message_3)?);
        assert_eq!("Message 2", alice_session.decrypt(&message_2)?);

        assert_eq!(alice_session.receiving_chains.len(), 2);

        Ok(())
    }

    #[test]
    fn libolm_unpickling() -> Result<()> {
        let (_, _, mut session, olm) = sessions()?;

        let plaintext = "It's a secret to everybody";
        let old_message = session.encrypt(plaintext);

        for _ in 0..9 {
            session.encrypt("Hello");
        }

        let message = session.encrypt("Hello");
        olm.decrypt(message.into())?;

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

        let mut unpickled = Session::from_libolm_pickle(&pickle, key)?;

        assert_eq!(olm.session_id(), unpickled.session_id());

        assert_eq!(unpickled.decrypt(&old_message)?, plaintext);

        let message = unpickled.encrypt(plaintext);

        assert_eq!(session.decrypt(&message)?, plaintext);

        Ok(())
    }

    #[test]
    fn session_pickling_roundtrip_is_identity() -> Result<()> {
        let (_, _, session, _) = sessions()?;

        let pickle = session.pickle_to_json_string();

        let unpickled_session: Session = serde_json::from_str(&pickle)?;
        let repickle = unpickled_session.pickle_to_json_string();

        let pickle: serde_json::Value = serde_json::from_str(&pickle)?;
        let repickle: serde_json::Value = serde_json::from_str(&repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }
}
