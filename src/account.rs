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

use std::collections::HashMap;

use rand::thread_rng;

use ed25519_dalek::{Keypair, PublicKey as Ed25519PublicKey};
use x25519_dalek::{PublicKey as Curve25591PublicKey, StaticSecret as Curve25591SecretKey};

use dashmap::DashMap;

use crate::utilities::encode;

use super::session::{OlmMessage, PrekeyMessage, Session, SessionKeys, Shared3DHSecret};

struct Ed25519Keypair {
    inner: Keypair,
    encoded_public_key: String,
}

impl Ed25519Keypair {
    fn new() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let encoded_public_key = encode(keypair.public.as_bytes());

        Self {
            inner: keypair,
            encoded_public_key,
        }
    }
}

struct Curve25519Keypair {
    secret_key: Curve25591SecretKey,
    public_key: Curve25591PublicKey,
    encoded_public_key: String,
}

impl Curve25519Keypair {
    fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = Curve25591SecretKey::new(&mut rng);
        let public_key = Curve25591PublicKey::from(&secret_key);
        let encoded_public_key = encode(public_key.as_bytes());

        Self {
            secret_key,
            public_key,
            encoded_public_key,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct KeyId(String);

struct OneTimeKeys {
    key_id: u64,
    public_keys: DashMap<KeyId, Curve25591PublicKey>,
    private_keys: DashMap<KeyId, Curve25591SecretKey>,
    reverse_public_keys: DashMap<Curve25591PublicKey, KeyId>,
}

impl OneTimeKeys {
    fn new() -> Self {
        Self {
            key_id: 0,
            public_keys: DashMap::new(),
            private_keys: DashMap::new(),
            reverse_public_keys: DashMap::new(),
        }
    }

    fn mark_as_published(&self) {
        self.public_keys.clear();
    }

    fn get_secret_key(&self, public_key: Curve25591PublicKey) -> Option<Curve25591SecretKey> {
        self.reverse_public_keys
            .remove(&public_key)
            .and_then(|(_, key_id)| self.private_keys.remove(&key_id).map(|(_, v)| v))
    }

    fn generate(&self, count: usize) {
        let mut rng = thread_rng();

        for _ in 0..count {
            let key_id = KeyId(encode(self.key_id.to_le_bytes()));
            let secret_key = Curve25591SecretKey::new(&mut rng);
            let public_key = Curve25591PublicKey::from(&secret_key);

            self.private_keys.insert(key_id.clone(), secret_key);
            self.public_keys.insert(key_id.clone(), public_key);
            self.reverse_public_keys.insert(public_key, key_id);
        }
    }
}

pub struct Account {
    signing_key: Ed25519Keypair,
    diffie_helman_key: Curve25519Keypair,
    one_time_keys: OneTimeKeys,
}

impl Account {
    pub fn new() -> Self {
        Self {
            signing_key: Ed25519Keypair::new(),
            diffie_helman_key: Curve25519Keypair::new(),
            one_time_keys: OneTimeKeys::new(),
        }
    }

    pub fn from_pickle() -> Self {
        todo!()
    }

    pub fn from_libolm_pickle() -> Self {
        todo!()
    }

    pub fn pickle() {}

    /// Get a reference to the account's public ed25519 key
    pub fn ed25519_key(&self) -> &Ed25519PublicKey {
        &self.signing_key.inner.public
    }

    fn calculate_shared_secret(
        &self,
        base_key: &Curve25591SecretKey,
        identity_key: &Curve25591PublicKey,
        one_time_key: &Curve25591PublicKey,
    ) -> Shared3DHSecret {
        let first_secret = self
            .diffie_helman_key
            .secret_key
            .diffie_hellman(one_time_key);
        let second_secret = base_key.diffie_hellman(identity_key);
        let third_secret = base_key.diffie_hellman(one_time_key);

        

        Shared3DHSecret::new(first_secret, second_secret, third_secret)
    }

    pub fn tripple_diffie_hellman(
        &self,
        identity_key: &Curve25591PublicKey,
        one_time_key: Curve25591PublicKey,
    ) -> Session {
        let rng = thread_rng();

        let base_key = Curve25591SecretKey::new(rng);
        let public_base_key = Curve25591PublicKey::from(&base_key);

        let shared_secret = self.calculate_shared_secret(&base_key, identity_key, &one_time_key);

        let session_keys = SessionKeys::new(*self.curve25519_key(), public_base_key, one_time_key);

        Session::new(shared_secret, session_keys)
    }

    pub fn session(&self, message: Vec<u8>) -> Session {
        let message = PrekeyMessage::from(message);
        let (public_one_time_key, base_key, identity_key, m) = message.decode().unwrap();

        let one_time_key = self
            .one_time_keys
            .get_secret_key(public_one_time_key)
            .unwrap();

        let first_secret = one_time_key.diffie_hellman(&identity_key);
        let second_secret = self.diffie_helman_key.secret_key.diffie_hellman(&base_key);
        let third_secret = one_time_key.diffie_hellman(&base_key);

        let shared_secret = Shared3DHSecret::new(first_secret, second_secret, third_secret);

        let message = OlmMessage::from(m);
        let decoded = message.decode().unwrap();

        Session::new_remote(shared_secret, decoded.ratchet_key)
    }

    /// Get a reference to the account's public curve25519 key
    pub fn curve25519_key(&self) -> &Curve25591PublicKey {
        &self.diffie_helman_key.public_key
    }

    /// Get a reference to the account's public curve25519 key as an unpadded
    /// base64 encoded string.
    pub fn curve25519_key_encoded(&self) -> &str {
        &self.diffie_helman_key.encoded_public_key
    }

    pub fn generate_one_time_keys(&self, count: usize) {
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
    use super::{Account, Curve25591PublicKey};
    use crate::utilities::{decode, encode};
    use olm_rs::{account::OlmAccount, session::OlmMessage};

    #[test]
    fn test_encryption() {
        let alice = Account::new();
        let bob = OlmAccount::new();

        bob.generate_one_time_keys(1);

        let one_time_key = bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .cloned()
            .next()
            .unwrap();

        let one_time_key_raw = decode(one_time_key).unwrap();
        let mut one_time_key = [0u8; 32];
        one_time_key.copy_from_slice(&one_time_key_raw);

        let identity_key_raw = decode(bob.parsed_identity_keys().curve25519()).unwrap();
        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&identity_key_raw);

        let one_time_key = Curve25591PublicKey::from(one_time_key);
        let identity_key = Curve25591PublicKey::from(identity_key);

        let mut alice_session = alice.tripple_diffie_hellman(&identity_key, one_time_key);

        let message = "It's a secret to everybody";

        let olm_message = alice_session.encrypt(message.as_bytes());
        let olm_message = encode(olm_message);
        let olm_message = OlmMessage::from_type_and_ciphertext(0, olm_message).unwrap();
        bob.mark_keys_as_published();

        if let OlmMessage::PreKey(m) = olm_message.clone() {
            let session = bob
                .create_inbound_session_from(alice.curve25519_key_encoded(), m)
                .expect("Can't create an Olm session");
            let plaintext = session
                .decrypt(olm_message)
                .expect("Can't decrypt ciphertext");
            assert_eq!(message, plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(second_text.as_bytes());
            let olm_message = encode(olm_message);
            let olm_message = OlmMessage::from_type_and_ciphertext(0, olm_message).unwrap();

            let plaintext = session
                .decrypt(olm_message)
                .expect("Can't decrypt second ciphertext");
            assert_eq!(second_text, plaintext);

            let reply_plain = "Yes, take this, it's dangerous out there";
            let (_, reply) = session.encrypt(reply_plain).to_tuple();
            let reply = decode(reply).unwrap();
            let plaintext = String::from_utf8(alice_session.decrypt(reply)).unwrap();

            assert_eq!(&plaintext, reply_plain);

            let another_reply = "Last one";
            let (_, reply) = session.encrypt(another_reply).to_tuple();
            let reply = decode(reply).unwrap();
            let plaintext = String::from_utf8(alice_session.decrypt(reply)).unwrap();
            assert_eq!(&plaintext, another_reply);

            let last_text = "Nope, I'll have the last word";
            let olm_message = alice_session.encrypt(last_text.as_bytes());
            let olm_message = encode(olm_message);
            let olm_message = OlmMessage::from_type_and_ciphertext(1, olm_message).unwrap();

            let plaintext = session
                .decrypt(olm_message)
                .expect("Can't decrypt second ciphertext");
            assert_eq!(last_text, plaintext);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_inbound_session_creation() {
        let alice = OlmAccount::new();
        let bob = Account::new();

        bob.generate_one_time_keys(1);

        let one_time_key = bob.one_time_keys().values().cloned().next().unwrap();

        let alice_session = alice
            .create_outbound_session(bob.curve25519_key_encoded(), &one_time_key)
            .unwrap();

        let text = "It's a secret to everybody";
        let (_, message) = alice_session.encrypt(text).to_tuple();
        let message = decode(message).unwrap();

        let mut session = bob.session(message.clone());

        let decrypted = session.decrypt_prekey(message);

        assert_eq!(text, String::from_utf8(decrypted).unwrap());

        let text = "Another secret";
        let (_, message) = alice_session.encrypt(text).to_tuple();
        let message = decode(message).unwrap();

        let decrypted = session.decrypt_prekey(message);

        assert_eq!(text, String::from_utf8(decrypted).unwrap());

        let text = "My first reply";

        let message = session.encrypt(text.as_bytes());
        let message = OlmMessage::from_type_and_ciphertext(1, encode(message)).unwrap();
        let decrypted = alice_session.decrypt(message).unwrap();

        assert_eq!(text, decrypted);
    }
}
