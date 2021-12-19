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

use arrayvec::ArrayVec;
use block_modes::BlockModeError;
use chain_key::RemoteChainKey;
use double_ratchet::DoubleRatchet;
use hmac::digest::MacError;
use ratchet::RemoteRatchetKey;
use receiver_chain::ReceiverChain;
use root_key::RemoteRootKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    messages::{DecodeError, InnerMessage, InnerPreKeyMessage, Message, OlmMessage, PreKeyMessage},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    utilities::{base64_decode, base64_encode},
    Curve25519PublicKey,
};

const MAX_RECEIVING_CHAINS: usize = 5;

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

pub struct Session {
    session_keys: SessionKeys,
    sending_ratchet: DoubleRatchet,
    receiving_chains: ChainStore,
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

        let local_ratchet = DoubleRatchet::inactive(root_key, remote_ratchet_key.clone());
        let remote_ratchet = ReceiverChain::new(remote_ratchet_key, remote_chain_key);

        let mut ratchet_store = ChainStore::new();
        ratchet_store.push(remote_ratchet);

        Self { session_keys, sending_ratchet: local_ratchet, receiving_chains: ratchet_store }
    }

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

    pub fn encrypt(&mut self, plaintext: &str) -> OlmMessage {
        let message = self.sending_ratchet.encrypt(plaintext);

        if self.has_received_message() {
            let message = message.into_vec();

            OlmMessage::Normal(Message { inner: base64_encode(message) })
        } else {
            let message = InnerPreKeyMessage::from_parts(
                &self.session_keys.one_time_key,
                &self.session_keys.base_key,
                &self.session_keys.identity_key,
                message.into_vec(),
            )
            .into_vec();

            OlmMessage::PreKey(PreKeyMessage { inner: base64_encode(message) })
        }
    }

    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String, DecryptionError> {
        let decrypted = match message {
            OlmMessage::Normal(m) => {
                let message = base64_decode(&m.inner)?;
                self.decrypt_normal(message)?
            }
            OlmMessage::PreKey(m) => {
                let message = base64_decode(&m.inner)?;
                self.decrypt_prekey(message)?
            }
        };

        Ok(String::from_utf8_lossy(&decrypted).to_string())
    }

    fn decrypt_prekey(&mut self, message: Vec<u8>) -> Result<Vec<u8>, DecryptionError> {
        let message = InnerPreKeyMessage::from(message);
        let (_, _, _, message) = message.decode()?;

        self.decrypt_normal(message)
    }

    fn decrypt_normal(&mut self, message: Vec<u8>) -> Result<Vec<u8>, DecryptionError> {
        let message = InnerMessage::from(message);
        let decoded = message.decode()?;

        let ratchet_key = RemoteRatchetKey::from(decoded.ratchet_key);

        if let Some(ratchet) = self.receiving_chains.find_ratchet(&ratchet_key) {
            Ok(ratchet.decrypt(&message, decoded.chain_index, &decoded.ciphertext, decoded.mac)?)
        } else {
            let (sending_ratchet, mut remote_ratchet) = self.sending_ratchet.advance(ratchet_key);

            let plaintext = remote_ratchet.decrypt(
                &message,
                decoded.chain_index,
                &decoded.ciphertext,
                decoded.mac,
            )?;

            self.sending_ratchet = sending_ratchet;
            self.receiving_chains.push(remote_ratchet);

            Ok(plaintext)
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
    use crate::{Account, Curve25519PublicKey};

    fn sessions() -> Result<(Account, OlmAccount, Session, OlmSession)> {
        let alice = Account::new();
        let bob = OlmAccount::new();
        bob.generate_one_time_keys(1);

        let one_time_key = bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .cloned()
            .next()
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
}
