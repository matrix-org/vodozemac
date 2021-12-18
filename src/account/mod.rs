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

mod fallback_keys;
mod one_time_keys;
mod types;

use std::collections::HashMap;

use ed25519_dalek::PublicKey as Ed25519PublicKey;
use fallback_keys::FallbackKeys;
use one_time_keys::OneTimeKeys;
use rand::thread_rng;
use thiserror::Error;
use types::{Curve25519Keypair, Ed25519Keypair, KeyId};
use x25519_dalek::StaticSecret as Curve25519SecretKey;

pub use crate::account::types::{Curve25519KeyError, Curve25519PublicKey};
use crate::{
    messages::{DecodeError, InnerMessage, InnerPreKeyMessage, PreKeyMessage},
    session::Session,
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    utilities::{base64_decode, base64_encode},
};

const MAX_NUMBER_OF_ONE_TIME_KEYS: usize = 100;

#[derive(Error, Debug)]
pub enum SessionCreationError {
    #[error("The pre-key message wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("The pre-key message couldn't be decoded: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("The pre-key message contained an unknown one-time key")]
    MissingOneTimeKey,
    #[error("The given identity key doesn't match the one in the pre-key message")]
    MismatchedIdentityKey,
}

/// An Olm account manages all cryptographic keys used on a device.
pub struct Account {
    /// A permanent Ed25519 key used for signing. Also known as the fingerprint
    /// key.
    signing_key: Ed25519Keypair,
    /// The permanent Curve25519 key used for 3DH. Also known as the sender key
    /// or the identity key.
    diffie_hellman_key: Curve25519Keypair,
    /// The ephemeral (one-time) Curve25519 keys used as part of the 3DH.
    one_time_keys: OneTimeKeys,
    /// The ephemeral Curve25519 keys used in lieu of a one-time key as part of
    /// the 3DH, in case we run out of those. We keep track of both the current
    /// and the previous fallback key in any given moment.
    fallback_keys: FallbackKeys,
}

impl Account {
    /// Create a new Account with new random identity keys.
    pub fn new() -> Self {
        Self {
            // TODO For libolm compatibility we'll want to be able to store
            // either an ed25519_dalek `ExpandedSecretKey` or a `SecretKey`.
            signing_key: Ed25519Keypair::new(),
            diffie_hellman_key: Curve25519Keypair::new(),
            // TODO actually limit the number of private one-time keys we can
            // hold. The server might attempt to fill our memory and trigger a
            // DOS otherwise.
            one_time_keys: OneTimeKeys::new(),
            fallback_keys: FallbackKeys::new(),
        }
    }

    /// Get a reference to the account's public ed25519 key
    pub fn ed25519_key(&self) -> &Ed25519PublicKey {
        self.signing_key.public_key()
    }

    /// Get a reference to the account's public ed25519 key as an unpadded
    /// base64 encoded string.
    pub fn ed25519_key_encoded(&self) -> &str {
        self.signing_key.public_key_encoded()
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

    /// Sign the given message using our ed25519 identity key.
    pub fn sign(&self, message: &str) -> String {
        self.signing_key.sign(message)
    }

    /// The maximum number of private one-time keys this `Account` will
    /// remember.
    ///
    /// The oldest keys will be dropped if we try to hold more than this value.
    pub fn max_number_of_one_time_keys(&self) -> usize {
        MAX_NUMBER_OF_ONE_TIME_KEYS
    }

    /// Create a `Session` with the given identity key and one-time key.
    pub fn create_outbound_session(
        &self,
        identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Session {
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

    /// Create a `Session` from the given pre-key message and identity key
    pub fn create_inbound_session(
        &mut self,
        their_identity_key: &Curve25519PublicKey,
        message: &PreKeyMessage,
    ) -> Result<Session, SessionCreationError> {
        let message = base64_decode(&message.inner)?;
        let message = InnerPreKeyMessage::from(message);

        let (public_one_time_key, remote_one_time_key, remote_identity_key, m) =
            message.decode()?;

        if their_identity_key != &remote_identity_key {
            Err(SessionCreationError::MismatchedIdentityKey)
        } else {
            let one_time_key = self
                .find_one_time_key(&public_one_time_key)
                .ok_or(SessionCreationError::MissingOneTimeKey)?;

            let shared_secret = RemoteShared3DHSecret::new(
                self.diffie_hellman_key.secret_key(),
                one_time_key,
                &remote_identity_key,
                &remote_one_time_key,
            );

            let session_keys =
                SessionKeys::new(remote_identity_key, remote_one_time_key, public_one_time_key);

            let message = InnerMessage::from(m);
            let decoded = message.decode()?;

            let session = Session::new_remote(shared_secret, decoded.ratchet_key, session_keys);

            self.remove_one_time_key(&public_one_time_key);

            Ok(session)
        }
    }

    /// Generates the supplied number of one time keys.
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.one_time_keys.generate(count);
    }

    /// Get the currently unpublished one-time keys.
    ///
    /// The one-time keys should be published to a server and marked as
    /// published using the `mark_keys_as_published()` method.
    pub fn one_time_keys(&self) -> HashMap<KeyId, Curve25519PublicKey> {
        self.one_time_keys.public_keys.iter().map(|(key_id, key)| (*key_id, *key)).collect()
    }

    /// Get the currently unpublished one-time keys in base64-encoded form.
    ///
    /// The one-time keys should be published to a server and marked as
    /// published using the `mark_keys_as_published()` method.
    pub fn one_time_keys_encoded(&self) -> HashMap<KeyId, String> {
        self.one_time_keys
            .public_keys
            .iter()
            .map(|(key_id, key)| (*key_id, key.to_base64()))
            .collect()
    }

    /// Generate a single new fallback key.
    ///
    /// The fallback key will be used by other users to establish a `Session` if
    /// all the one-time keys on the server have been used up.
    pub fn generate_fallback_key(&mut self) {
        self.fallback_keys.generate_fallback_key()
    }

    /// Get the currently unpublished fallback key.
    ///
    /// The fallback key should be published just like the one-time keys, after
    /// it has been successfully published it needs to be marked as published
    /// using the `mark_keys_as_published()` method as well.
    pub fn fallback_key(&self) -> HashMap<KeyId, String> {
        let fallback_key = self.fallback_keys.unpublished_fallback_key();

        if let Some(fallback_key) = fallback_key {
            HashMap::from([(
                fallback_key.key_id(),
                base64_encode(fallback_key.public_key().as_bytes()),
            )])
        } else {
            HashMap::new()
        }
    }

    /// The `Account` stores at most two private parts of the fallback key. This
    /// method lets us forget the previously used fallback key.
    pub fn forget_fallback_key(&mut self) -> bool {
        self.fallback_keys.forget_previous_fallback_key().is_some()
    }

    /// Mark all currently unpublished one-time and fallback keys as published.
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
    use anyhow::{bail, Context, Result};
    use olm_rs::{account::OlmAccount, session::OlmMessage as LibolmOlmMessage};

    use super::Account;
    use crate::{messages::OlmMessage, Curve25519PublicKey as PublicKey};

    #[test]
    fn test_vodozemac_libolm_communication() -> Result<()> {
        // vodozemac account
        let alice = Account::new();
        // libolm account
        let bob = OlmAccount::new();

        bob.generate_one_time_keys(1);

        let one_time_key = bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .cloned()
            .next()
            .expect("Didn't find a valid one-time key");

        bob.mark_keys_as_published();

        let identity_keys = bob.parsed_identity_keys();
        let curve25519_key = PublicKey::from_base64(identity_keys.curve25519())?;
        let one_time_key = PublicKey::from_base64(&one_time_key)?;
        let mut alice_session = alice.create_outbound_session(curve25519_key, one_time_key);

        let message = "It's a secret to everybody";
        let olm_message: LibolmOlmMessage = alice_session.encrypt(message).into();

        if let LibolmOlmMessage::PreKey(m) = olm_message.clone() {
            let libolm_session =
                bob.create_inbound_session_from(alice.curve25519_key_encoded(), m)?;
            assert_eq!(alice_session.session_id(), libolm_session.session_id());

            let plaintext = libolm_session.decrypt(olm_message)?;
            assert_eq!(message, plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(second_text).into();

            let plaintext = libolm_session.decrypt(olm_message)?;
            assert_eq!(second_text, plaintext);

            let reply_plain = "Yes, take this, it's dangerous out there";
            let reply = libolm_session.encrypt(reply_plain).into();
            let plaintext = alice_session.decrypt(&reply)?;

            assert_eq!(&plaintext, reply_plain);

            let another_reply = "Last one";
            let reply = libolm_session.encrypt(another_reply).into();
            let plaintext = alice_session.decrypt(&reply)?;
            assert_eq!(&plaintext, another_reply);

            let last_text = "Nope, I'll have the last word";
            let olm_message = alice_session.encrypt(last_text).into();

            let plaintext = libolm_session.decrypt(olm_message)?;
            assert_eq!(last_text, plaintext);
        } else {
            bail!("Received a invalid message type {:?}", olm_message);
        }

        Ok(())
    }

    #[test]
    fn test_vodozemac_vodozemac_communication() -> Result<()> {
        // Both of these are vodozemac accounts.
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);

        let mut alice_session = alice.create_outbound_session(
            *bob.curve25519_key(),
            *bob.one_time_keys()
                .iter()
                .next()
                .context("Failed getting bob's OTK, which should never happen here.")?
                .1,
        );

        bob.mark_keys_as_published();

        let message = "It's a secret to everybody";
        let olm_message: OlmMessage = alice_session.encrypt(message);

        if let OlmMessage::PreKey(m) = olm_message.clone() {
            let mut bob_session = bob.create_inbound_session(alice.curve25519_key(), &m)?;
            assert_eq!(alice_session.session_id(), bob_session.session_id());

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(message, plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(second_text);

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(second_text, plaintext);

            let reply_plain = "Yes, take this, it's dangerous out there";
            let reply = bob_session.encrypt(reply_plain);
            let plaintext = alice_session.decrypt(&reply)?;

            assert_eq!(&plaintext, reply_plain);

            let another_reply = "Last one";
            let reply = bob_session.encrypt(another_reply);
            let plaintext = alice_session.decrypt(&reply)?;
            assert_eq!(&plaintext, another_reply);

            let last_text = "Nope, I'll have the last word";
            let olm_message = alice_session.encrypt(last_text);

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(last_text, plaintext);
        }

        Ok(())
    }

    #[test]
    fn test_inbound_session_creation() -> Result<()> {
        let alice = OlmAccount::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);

        let one_time_key = bob
            .one_time_keys_encoded()
            .values()
            .cloned()
            .next()
            .expect("Didn't find a valid one-time key");

        let alice_session =
            alice.create_outbound_session(bob.curve25519_key_encoded(), &one_time_key)?;

        let text = "It's a secret to everybody";
        let message = alice_session.encrypt(text).into();

        let identity_key = PublicKey::from_base64(alice.parsed_identity_keys().curve25519())?;

        let mut session = if let OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session(&identity_key, m)?
        } else {
            bail!("Got invalid message type from olm_rs {:?}", message);
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.one_time_keys.private_keys.is_empty());

        let decrypted = session.decrypt(&message)?;
        assert_eq!(text, decrypted);

        Ok(())
    }

    #[test]
    fn test_inbound_session_creation_using_fallback_keys() -> Result<()> {
        let alice = OlmAccount::new();
        let mut bob = Account::new();

        bob.generate_fallback_key();

        let one_time_key =
            bob.fallback_key().values().cloned().next().expect("Didn't find a valid fallback key");
        assert!(bob.one_time_keys.private_keys.is_empty());

        let alice_session =
            alice.create_outbound_session(bob.curve25519_key_encoded(), &one_time_key)?;

        let text = "It's a secret to everybody";

        let message = alice_session.encrypt(text).into();
        let identity_key = PublicKey::from_base64(alice.parsed_identity_keys().curve25519())?;

        let mut session = if let crate::messages::OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session(&identity_key, m)?
        } else {
            bail!("Got invalid message type from olm_rs");
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.fallback_keys.fallback_key.is_some());

        let decrypted = session.decrypt(&message)?;

        assert_eq!(text, decrypted);

        Ok(())
    }
}
