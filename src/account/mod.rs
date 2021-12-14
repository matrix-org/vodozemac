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

mod types;

use std::collections::HashMap;

use ed25519_dalek::PublicKey as Ed25519PublicKey;
use rand::thread_rng;
use types::{Curve25519Keypair, Ed25519Keypair, KeyId, OneTimeKeys};
use x25519_dalek::{PublicKey as Curve25591PublicKey, StaticSecret as Curve25591SecretKey};

use crate::{
    messages::PreKeyMessage,
    session::{
        InnerMessage, InnerPreKeyMessage, RemoteShared3DHSecret, Session, SessionKeys,
        Shared3DHSecret,
    },
    utilities::{decode, encode},
};

pub struct Account {
    signing_key: Ed25519Keypair,
    diffie_helman_key: Curve25519Keypair,
    one_time_keys: OneTimeKeys,
}

impl Account {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            signing_key: Ed25519Keypair::new(),
            diffie_helman_key: Curve25519Keypair::new(),
            one_time_keys: OneTimeKeys::new(),
        }
    }

    pub fn unpickle() -> Self {
        // TODO
        Self::new()
    }

    pub fn from_libolm_pickle() -> Self {
        todo!()
    }

    pub fn pickle(&self) -> String {
        "TEST_PICKLE".to_string()
    }

    pub fn sign(&self, message: &str) -> String {
        self.signing_key.sign(message)
    }

    pub fn max_number_of_one_time_keys(&self) -> usize {
        50
    }

    /// Get a reference to the account's public ed25519 key
    pub fn ed25519_key(&self) -> &Ed25519PublicKey {
        self.signing_key.public_key()
    }

    pub fn create_outbound_session(&self, identity_key: &str, one_time_key: &str) -> Session {
        let mut id_key = [0u8; 32];
        let mut one_time = [0u8; 32];

        // TODO check the length of the string

        let identity_key = decode(identity_key).unwrap();
        let one_time_key = decode(one_time_key).unwrap();

        id_key.copy_from_slice(&identity_key);
        one_time.copy_from_slice(&one_time_key);

        let identity_key = Curve25591PublicKey::from(id_key);
        let one_time_key = Curve25591PublicKey::from(one_time);

        let rng = thread_rng();

        let base_key = Curve25591SecretKey::new(rng);
        let public_base_key = Curve25591PublicKey::from(&base_key);

        let shared_secret = Shared3DHSecret::new(
            self.diffie_helman_key.secret_key(),
            &base_key,
            &identity_key,
            &one_time_key,
        );

        let session_keys = SessionKeys::new(*self.curve25519_key(), public_base_key, one_time_key);

        Session::new(shared_secret, session_keys)
    }

    pub fn create_inbound_session_from(
        &self,
        their_identity_key: &Curve25591PublicKey,
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
        let one_time_key = self.one_time_keys.get_secret_key(public_one_time_key).unwrap();

        let shared_secret = RemoteShared3DHSecret::new(
            self.diffie_helman_key.secret_key(),
            &one_time_key,
            &remote_identity_key,
            &remote_one_time_key,
        );

        let message = InnerMessage::from(m);
        let decoded = message.decode().unwrap();

        Session::new_remote(shared_secret, decoded.ratchet_key)
    }

    /// Get a reference to the account's public curve25519 key
    pub fn curve25519_key(&self) -> &Curve25591PublicKey {
        self.diffie_helman_key.public_key()
    }

    /// Get a reference to the account's public curve25519 key as an unpadded
    /// base64 encoded string.
    pub fn curve25519_key_encoded(&self) -> &str {
        self.diffie_helman_key.public_key_encoded()
    }

    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.one_time_keys.generate(count);
    }

    pub fn one_time_keys(&self) -> HashMap<KeyId, String> {
        self.one_time_keys
            .public_keys
            .iter()
            .map(|i| (i.key().clone(), encode(i.value().as_bytes())))
            .collect()
    }

    pub fn mark_keys_as_published(&self) {
        self.one_time_keys.mark_as_published();
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

        let decrypted = session.decrypt(&message);

        assert_eq!(text, decrypted);
    }
}
