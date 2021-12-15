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

mod fallback_keys;
mod one_time_keys;
mod types;

use std::collections::HashMap;

use ed25519_dalek::PublicKey as Ed25519PublicKey;
use fallback_keys::FallbackKeys;
use one_time_keys::OneTimeKeys;
use rand::thread_rng;
use types::{Curve25519Keypair, Ed25519Keypair, KeyId};
use x25519_dalek::{PublicKey as Curve25519PublicKey, StaticSecret as Curve25519SecretKey};

use crate::{
    messages::{InnerMessage, InnerPreKeyMessage, PreKeyMessage},
    session::Session,
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    utilities::{decode, encode},
};

pub struct Account {
    signing_key: Ed25519Keypair,
    diffie_hellman_key: Curve25519Keypair,
    one_time_keys: OneTimeKeys,
    fallback_keys: FallbackKeys,
}

impl Account {
    pub fn new() -> Self {
        Self {
            signing_key: Ed25519Keypair::new(),
            diffie_hellman_key: Curve25519Keypair::new(),
            one_time_keys: OneTimeKeys::new(),
            fallback_keys: FallbackKeys::new(),
        }
    }

    /// Get a reference to the account's public ed25519 key
    pub fn ed25519_key(&self) -> &Ed25519PublicKey {
        self.signing_key.public_key()
    }

    /// Get a reference to the account's public curve25519 key
    pub fn curve25519_key(&self) -> &Curve25519PublicKey {
        self.diffie_hellman_key.public_key()
    }

    /// Get a reference to the account's public curve25519 key as an unpadded
    /// base64 encoded string.
    pub fn curve25519_key_encoded(&self) -> &str {
        self.diffie_hellman_key.public_key_encoded()
    }

    pub fn sign(&self, message: &str) -> String {
        self.signing_key.sign(message)
    }

    pub fn from_pickle() -> Self {
        // TODO
        Self::new()
    }

    pub fn from_libolm_pickle() -> Self {
        todo!()
    }

    pub fn pickle(&self) -> String {
        "TEST_PICKLE".to_string()
    }

    pub fn max_number_of_one_time_keys(&self) -> usize {
        50
    }

    pub fn create_outbound_session(&self, identity_key: &str, one_time_key: &str) -> Session {
        let mut id_key = [0u8; 32];
        let mut one_time = [0u8; 32];

        // TODO check the length of the string

        let identity_key = decode(identity_key).unwrap();
        let one_time_key = decode(one_time_key).unwrap();

        id_key.copy_from_slice(&identity_key);
        one_time.copy_from_slice(&one_time_key);

        let identity_key = Curve25519PublicKey::from(id_key);
        let one_time_key = Curve25519PublicKey::from(one_time);

        let rng = thread_rng();

        let base_key = Curve25519SecretKey::new(rng);
        let public_base_key = Curve25519PublicKey::from(&base_key);

        let shared_secret = Shared3DHSecret::new(
            self.diffie_hellman_key.secret_key(),
            &base_key,
            &identity_key,
            &one_time_key,
        );

        let session_keys = SessionKeys::new(*self.curve25519_key(), public_base_key, one_time_key);

        Session::new(shared_secret, session_keys)
    }

    fn find_one_time_key(&self, public_key: &Curve25519PublicKey) -> Option<&Curve25519SecretKey> {
        self.one_time_keys
            .get_secret_key(public_key)
            .or_else(|| self.fallback_keys.get_secret_key(public_key))
    }

    fn remove_one_time_key(
        &mut self,
        public_key: &Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.one_time_keys.remove_secret_key(public_key)
    }

    pub fn create_inbound_session_from(
        &mut self,
        their_identity_key: &Curve25519PublicKey,
        message: &PreKeyMessage,
    ) -> Session {
        let message = decode(&message.inner).unwrap();
        let message = InnerPreKeyMessage::from(message);

        let (public_one_time_key, remote_one_time_key, remote_identity_key, m) =
            message.decode().unwrap();

        if their_identity_key != &remote_identity_key {
            // TODO turn this into an error
            panic!("Missmatched identity keys");
        }

        // TODO this one should be an error as well.
        let one_time_key = self.find_one_time_key(&public_one_time_key).unwrap();

        let shared_secret = RemoteShared3DHSecret::new(
            self.diffie_hellman_key.secret_key(),
            one_time_key,
            &remote_identity_key,
            &remote_one_time_key,
        );

        let session_keys =
            SessionKeys::new(remote_identity_key, remote_one_time_key, public_one_time_key);

        let message = InnerMessage::from(m);
        let decoded = message.decode().unwrap();

        let session = Session::new_remote(shared_secret, decoded.ratchet_key, session_keys);

        self.remove_one_time_key(&public_one_time_key);

        session
    }

    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.one_time_keys.generate(count);
    }

    pub fn one_time_keys(&self) -> HashMap<KeyId, String> {
        self.one_time_keys
            .public_keys
            .iter()
            .map(|(key_id, key)| (*key_id, encode(key.as_bytes())))
            .collect()
    }

    pub fn generate_fallback_key(&mut self) {
        self.fallback_keys.generate_fallback_key()
    }

    pub fn fallback_keys(&self) -> HashMap<KeyId, String> {
        let fallback_key = self.fallback_keys.unpublished_fallback_key();

        if let Some(fallback_key) = fallback_key {
            HashMap::from([(fallback_key.key_id(), encode(fallback_key.public_key().as_bytes()))])
        } else {
            HashMap::new()
        }
    }

    pub fn forget_fallback_key(&mut self) -> bool {
        self.fallback_keys.forget_previous_fallback_key().is_some()
    }

    pub fn mark_keys_as_published(&mut self) {
        self.one_time_keys.mark_as_published();
        self.fallback_keys.mark_as_published();
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use olm_rs::{account::OlmAccount, session::OlmMessage};

    use super::Account;
    use crate::utilities::decode;

    #[test]
    fn test_encryption() {
        let alice = Account::new();
        let bob = OlmAccount::new();

        bob.generate_one_time_keys(1);

        let one_time_key =
            bob.parsed_one_time_keys().curve25519().values().cloned().next().unwrap();

        let identity_keys = bob.parsed_identity_keys();
        let mut alice_session =
            alice.create_outbound_session(identity_keys.curve25519(), &one_time_key);

        let message = "It's a secret to everybody";

        let olm_message: OlmMessage = alice_session.encrypt(message).into();
        bob.mark_keys_as_published();

        if let OlmMessage::PreKey(m) = olm_message.clone() {
            let session = bob
                .create_inbound_session_from(alice.curve25519_key_encoded(), m)
                .expect("Can't create an Olm session");
            assert_eq!(alice_session.session_id(), session.session_id());

            let plaintext = session.decrypt(olm_message).expect("Can't decrypt ciphertext");
            assert_eq!(message, plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(second_text).into();

            let plaintext = session.decrypt(olm_message).expect("Can't decrypt second ciphertext");
            assert_eq!(second_text, plaintext);

            let reply_plain = "Yes, take this, it's dangerous out there";
            let reply = session.encrypt(reply_plain).into();
            let plaintext = alice_session.decrypt(&reply);

            assert_eq!(&plaintext, reply_plain);

            let another_reply = "Last one";
            let reply = session.encrypt(another_reply).into();
            let plaintext = alice_session.decrypt(&reply);
            assert_eq!(&plaintext, another_reply);

            let last_text = "Nope, I'll have the last word";
            let olm_message = alice_session.encrypt(last_text).into();

            let plaintext = session.decrypt(olm_message).expect("Can't decrypt second ciphertext");
            assert_eq!(last_text, plaintext);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_inbound_session_creation() {
        let alice = OlmAccount::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);

        let one_time_key = bob.one_time_keys().values().cloned().next().unwrap();

        let alice_session =
            alice.create_outbound_session(bob.curve25519_key_encoded(), &one_time_key).unwrap();

        let text = "It's a secret to everybody";

        let message: crate::messages::OlmMessage = alice_session.encrypt(text).into();

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&decode(alice.parsed_identity_keys().curve25519()).unwrap());
        let identity_key = x25519_dalek::PublicKey::from(identity_key);

        let mut session = if let crate::messages::OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session_from(&identity_key, m)
        } else {
            panic!("Got invalid message type from olm_rs");
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.one_time_keys.private_keys.is_empty());

        let decrypted = session.decrypt(&message);

        assert_eq!(text, decrypted);
    }

    #[test]
    fn test_inbound_session_creation_using_fallback_keys() {
        let alice = OlmAccount::new();
        let mut bob = Account::new();

        bob.generate_fallback_key();

        let one_time_key = bob.fallback_keys().values().cloned().next().unwrap();
        assert!(bob.one_time_keys.private_keys.is_empty());

        let alice_session =
            alice.create_outbound_session(bob.curve25519_key_encoded(), &one_time_key).unwrap();

        let text = "It's a secret to everybody";

        let message: crate::messages::OlmMessage = alice_session.encrypt(text).into();

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&decode(alice.parsed_identity_keys().curve25519()).unwrap());
        let identity_key = x25519_dalek::PublicKey::from(identity_key);

        let mut session = if let crate::messages::OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session_from(&identity_key, m)
        } else {
            panic!("Got invalid message type from olm_rs");
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.fallback_keys.fallback_key.is_some());

        let decrypted = session.decrypt(&message);

        assert_eq!(text, decrypted);
    }
}
