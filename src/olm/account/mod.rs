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

use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek, SeekFrom},
    ops::Deref,
};

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{ReusableSecret, StaticSecret as Curve25519SecretKey};
use zeroize::Zeroize;

use self::{
    fallback_keys::{FallbackKey, FallbackKeys, FallbackKeysPickle},
    one_time_keys::{OneTimeKeys, OneTimeKeysPickle},
};
use super::{
    messages::{InnerMessage, InnerPreKeyMessage, PreKeyMessage},
    session::{DecryptionError, Session},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
};
use crate::{
    types::{
        Curve25519Keypair, Curve25519KeypairPickle, Curve25519PublicKey, Ed25519Keypair,
        Ed25519KeypairPickle, Ed25519KeypairUnpicklingError, Ed25519PublicKey, KeyId,
    },
    utilities::{base64_decode, base64_encode},
    DecodeError,
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
    #[error("The message that was used to establish the Session couldn't be decrypted")]
    Decryption(#[from] DecryptionError),
}

/// Return type for the creation of inbound [`Session`] objects.
#[derive(Debug)]
pub struct InboundCreationResult {
    /// The [`Session`] that was created from a pre-key message.
    pub session: Session,
    /// The plaintext of the pre-key message.
    pub plaintext: String,
}

/// An Olm account manages all cryptographic keys used on a device.
#[derive(Deserialize)]
#[serde(try_from = "AccountPickle")]
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
            signing_key: Ed25519Keypair::new(),
            diffie_hellman_key: Curve25519Keypair::new(),
            // TODO actually limit the number of private one-time keys we can
            // hold. The server might attempt to fill our memory and trigger a
            // DOS otherwise.
            one_time_keys: OneTimeKeys::new(),
            fallback_keys: FallbackKeys::new(),
        }
    }

    /// Get a reference to the account's public Ed25519 key
    pub fn ed25519_key(&self) -> &Ed25519PublicKey {
        self.signing_key.public_key()
    }

    /// Get a reference to the account's public Ed25519 key as an unpadded
    /// base64 encoded string.
    pub fn ed25519_key_encoded(&self) -> &str {
        self.signing_key.public_key_encoded()
    }

    /// Get a reference to the account's public Curve25519 key
    pub fn curve25519_key(&self) -> &Curve25519PublicKey {
        self.diffie_hellman_key.public_key()
    }

    /// Get a reference to the account's public Curve25519 key as an unpadded
    /// base64-encoded string.
    pub fn curve25519_key_encoded(&self) -> &str {
        self.diffie_hellman_key.public_key_encoded()
    }

    /// Sign the given message using our Ed25519 fingerprint key.
    pub fn sign(&self, message: &str) -> String {
        self.signing_key.sign(message.as_bytes()).to_base64()
    }

    /// Convert the account into a struct which implements [`serde::Serialize`]
    /// and [`serde::Deserialize`].
    pub fn pickle(&self) -> AccountPickle {
        AccountPickle {
            signing_key: self.signing_key.clone().into(),
            diffie_hellman_key: self.diffie_hellman_key.clone().into(),
            one_time_keys: self.one_time_keys.clone().into(),
            fallback_keys: self.fallback_keys.clone(),
        }
    }

    /// Pickle the Olm account and serialize it to a JSON string.
    ///
    /// The string is wrapped in [`AccountPickledJSON`] which can be derefed to
    /// access the content as a string slice. The string will zeroize itself
    /// when it drops to prevent secrets contained inside from lingering in
    /// memory.
    pub fn pickle_to_json_string(&self) -> AccountPickledJSON {
        let pickle: AccountPickle = self.pickle();
        AccountPickledJSON(
            serde_json::to_string_pretty(&pickle).expect("Account serialization failed."),
        )
    }

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

        let base_key = ReusableSecret::new(rng);
        let public_base_key = Curve25519PublicKey::from(&base_key);

        let shared_secret = Shared3DHSecret::new(
            self.diffie_hellman_key.secret_key(),
            &base_key,
            &identity_key,
            &one_time_key,
        );

        let session_keys = SessionKeys {
            identity_key: *self.curve25519_key(),
            base_key: public_base_key,
            one_time_key,
        };

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

    /// Create a [`Session`] from the given pre-key message and identity key
    pub fn create_inbound_session(
        &mut self,
        their_identity_key: &Curve25519PublicKey,
        message: &PreKeyMessage,
    ) -> Result<InboundCreationResult, SessionCreationError> {
        let message = base64_decode(&message.inner)?;
        let message = InnerPreKeyMessage::from(message);

        let (public_one_time_key, remote_one_time_key, remote_identity_key, m) =
            message.decode()?;

        if their_identity_key != &remote_identity_key {
            Err(SessionCreationError::MismatchedIdentityKey)
        } else {
            // Find the matching private key that the message claims to have
            // used to create the Session that encrypted it.
            let one_time_key = self
                .find_one_time_key(&public_one_time_key)
                .ok_or(SessionCreationError::MissingOneTimeKey)?;

            // Construct a 3DH shared secret from the various curve25519 keys.
            let shared_secret = RemoteShared3DHSecret::new(
                self.diffie_hellman_key.secret_key(),
                one_time_key,
                &remote_identity_key,
                &remote_one_time_key,
            );

            // These will be used to uniquely identify the Session.
            let session_keys = SessionKeys {
                identity_key: remote_identity_key,
                base_key: remote_one_time_key,
                one_time_key: public_one_time_key,
            };

            let message = InnerMessage::from(m);
            let decoded = message.decode()?;

            // Create a Session, AKA a double ratchet, this one will have an
            // inactive sending chain until we decide to encrypt a message.
            let mut session = Session::new_remote(shared_secret, decoded.ratchet_key, session_keys);

            // Decrypt the message to check if the Session is actually valid.
            let plaintext = session.decrypt_decoded(message, decoded)?;
            let plaintext = String::from_utf8_lossy(&plaintext).to_string();

            // We only drop the one-time key now, this is why we can't use a
            // one-time key type that takes `self`. If we didn't do this,
            // someone could maliciously pretend to use up our one-time key and
            // make us drop the private part. Unsuspecting users that actually
            // try to use such an one-time key won't be able to commnuicate with
            // us. This is strictly worse than the one-time key exhaustion
            // scenario.
            self.remove_one_time_key(&public_one_time_key);

            Ok(InboundCreationResult { session, plaintext })
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
    pub fn one_time_keys_encoded(&self) -> HashMap<String, String> {
        self.one_time_keys
            .public_keys
            .iter()
            .map(|(key_id, key)| (key_id.to_base64(), key.to_base64()))
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

    /// Create an [`Account`] object by unpickling an account pickle in libolm
    /// legacy pickle format.
    ///
    /// Such pickles are encrypted and need to first be decrypted using
    /// `pickle_key`.
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &str,
    ) -> Result<Self, crate::LibolmUnpickleError> {
        use crate::{
            cipher::Cipher,
            utilities::{read_bool, read_curve_key, read_u32},
        };

        const PICKLE_VERSION: u32 = 4;

        let cipher = Cipher::new_pickle(pickle_key.as_ref());
        let decoded = base64_decode(pickle)?;
        let decrypted = cipher.decrypt_pickle(&decoded)?;

        let mut cursor = Cursor::new(decrypted);
        let version = read_u32(&mut cursor)?;

        if version != PICKLE_VERSION {
            Err(crate::LibolmUnpickleError::Version(PICKLE_VERSION, version))
        } else {
            // We skip the public ed25519 key, we'll create it from the private
            // key.
            cursor.seek(SeekFrom::Current(32))?;
            let mut private_key = [0u8; 64];
            cursor.read_exact(&mut private_key)?;

            let signing_key = Ed25519Keypair::from_expanded_key(&private_key)?;
            private_key.zeroize();

            let secret_key = read_curve_key(&mut cursor)?;
            let public_key = Curve25519PublicKey::from(&secret_key);

            let diffie_hellman_key = Curve25519Keypair {
                secret_key,
                public_key,
                encoded_public_key: public_key.to_base64(),
            };

            let number_of_one_time_keys = read_u32(&mut cursor)?;

            let unpickle_curve_key = |cursor: &mut Cursor<Vec<u8>>| -> Result<
                (KeyId, bool, Curve25519SecretKey),
                crate::LibolmUnpickleError,
            > {
                let key_id = KeyId(read_u32(cursor)? as u64);
                let published = read_bool(cursor)?;
                let private_key = read_curve_key(cursor)?;

                Ok((key_id, published, private_key))
            };

            let mut one_time_keys = HashMap::new();
            let mut unpublished_one_time_keys = HashMap::new();
            let mut reverse_one_time_keys = HashMap::new();

            for _ in 0..number_of_one_time_keys {
                let (key_id, published, private) = unpickle_curve_key(&mut cursor)?;

                let public = Curve25519PublicKey::from(&private);

                one_time_keys.insert(key_id, private);
                reverse_one_time_keys.insert(public, key_id);

                if !published {
                    unpublished_one_time_keys.insert(key_id, public);
                }
            }

            let max_key_id = one_time_keys.keys().max().copied().unwrap_or(KeyId(0));

            let mut number_of_fallback_keys = [0u8; 1];
            cursor.read_exact(&mut number_of_fallback_keys)?;
            let number_of_fallback_keys = number_of_fallback_keys[0];

            let fallback_key = if number_of_fallback_keys >= 1 {
                let (key_id, published, key) = unpickle_curve_key(&mut cursor)?;

                Some(FallbackKey { key_id, key, published })
            } else {
                None
            };

            let previous_fallback_key = if number_of_fallback_keys >= 2 {
                let (key_id, published, key) = unpickle_curve_key(&mut cursor)?;

                Some(FallbackKey { key_id, key, published })
            } else {
                None
            };

            Ok(Self {
                signing_key,
                diffie_hellman_key,
                one_time_keys: OneTimeKeys {
                    key_id: max_key_id.0 + 1,
                    public_keys: unpublished_one_time_keys,
                    private_keys: one_time_keys,
                    reverse_public_keys: reverse_one_time_keys,
                },
                fallback_keys: FallbackKeys {
                    key_id: fallback_key.as_ref().map(|k| k.key_id().0 + 1).unwrap_or(0),
                    fallback_key,
                    previous_fallback_key,
                },
            })
        }
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccountPickle {
    signing_key: Ed25519KeypairPickle,
    diffie_hellman_key: Curve25519KeypairPickle,
    one_time_keys: OneTimeKeysPickle,
    fallback_keys: FallbackKeysPickle,
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`Account::pickle`].
impl AccountPickle {
    /// Convert the pickle format back into an [`Account`].
    pub fn unpickle(self) -> Result<Account, AccountUnpicklingError> {
        self.try_into()
    }
}

impl TryFrom<AccountPickle> for Account {
    type Error = AccountUnpicklingError;

    fn try_from(pickle: AccountPickle) -> Result<Self, AccountUnpicklingError> {
        Ok(Self {
            signing_key: pickle.signing_key.try_into()?,
            diffie_hellman_key: pickle.diffie_hellman_key.into(),
            one_time_keys: pickle.one_time_keys.into(),
            fallback_keys: pickle.fallback_keys,
        })
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct AccountPickledJSON(String);

impl AccountPickledJSON {
    /// Access the serialized content as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Try to convert the serialized JSON string back into an [`Account`].
    pub fn unpickle(self) -> Result<Account, AccountUnpicklingError> {
        let pickle: AccountPickle = serde_json::from_str(&self.0)?;
        pickle.unpickle()
    }
}

impl AsRef<str> for AccountPickledJSON {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for AccountPickledJSON {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[derive(Error, Debug)]
pub enum AccountUnpicklingError {
    #[error("Invalid signing key: {0}")]
    InvalidSigningKey(#[from] Ed25519KeypairUnpicklingError),
    #[error("Pickle format corrupted: {0}")]
    CorruptedPickle(#[from] serde_json::error::Error),
}

#[cfg(test)]
mod test {
    use anyhow::{bail, Context, Result};
    use olm_rs::{account::OlmAccount, session::OlmMessage as LibolmOlmMessage, PicklingMode};

    use super::{Account, InboundCreationResult, SessionCreationError};
    use crate::{
        cipher::Mac,
        olm::messages::{OlmMessage, PreKeyMessage},
        utilities::{base64_decode, base64_encode},
        Curve25519PublicKey as PublicKey,
    };

    #[test]
    fn vodozemac_libolm_communication() -> Result<()> {
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
    fn vodozemac_vodozemac_communication() -> Result<()> {
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

        if let OlmMessage::PreKey(m) = olm_message {
            let InboundCreationResult { session: mut bob_session, plaintext } =
                bob.create_inbound_session(alice.curve25519_key(), &m)?;
            assert_eq!(alice_session.session_id(), bob_session.session_id());

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
    fn inbound_session_creation() -> Result<()> {
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

        let InboundCreationResult { session, plaintext } = if let OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session(&identity_key, m)?
        } else {
            bail!("Got invalid message type from olm_rs {:?}", message);
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.one_time_keys.private_keys.is_empty());

        assert_eq!(text, plaintext);

        Ok(())
    }

    #[test]
    fn inbound_session_creation_using_fallback_keys() -> Result<()> {
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

        let InboundCreationResult { session, plaintext } = if let OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session(&identity_key, m)?
        } else {
            bail!("Got invalid message type from olm_rs");
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.fallback_keys.fallback_key.is_some());

        assert_eq!(text, plaintext);

        Ok(())
    }

    #[test]
    fn account_pickling_roundtrip_is_identity() -> Result<()> {
        let mut account = Account::new();

        account.generate_one_time_keys(50);

        // Generate two fallback keys so the previous fallback key field gets populated.
        account.generate_fallback_key();
        account.generate_fallback_key();

        let pickle = account.pickle_to_json_string();

        let unpickled_account: Account = serde_json::from_str(&pickle)?;
        let repickle = unpickled_account.pickle_to_json_string();

        let pickle: serde_json::Value = serde_json::from_str(&pickle)?;
        let repickle: serde_json::Value = serde_json::from_str(&repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    fn libolm_unpickling() -> Result<()> {
        let olm = OlmAccount::new();
        olm.generate_one_time_keys(10);
        olm.generate_fallback_key();

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

        let unpickled = Account::from_libolm_pickle(&pickle, key)?;

        assert_eq!(olm.parsed_identity_keys().ed25519(), unpickled.ed25519_key_encoded());
        assert_eq!(olm.parsed_identity_keys().curve25519(), unpickled.curve25519_key_encoded());

        let mut olm_one_time_keys: Vec<_> =
            olm.parsed_one_time_keys().curve25519().values().map(|k| k.to_owned()).collect();
        let mut one_time_keys: Vec<_> =
            unpickled.one_time_keys_encoded().values().map(|k| k.to_owned()).collect();

        olm_one_time_keys.sort();
        one_time_keys.sort();
        assert_eq!(olm_one_time_keys, one_time_keys);

        let olm_fallback_key =
            olm.parsed_fallback_key().expect("libolm should have a fallback key");
        assert_eq!(
            olm_fallback_key.curve25519(),
            unpickled.fallback_key().values().next().expect("We should have a fallback key")
        );

        Ok(())
    }

    #[test]
    fn signing_with_expanded_key() -> Result<()> {
        let olm = OlmAccount::new();
        olm.generate_one_time_keys(10);
        olm.generate_fallback_key();

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

        let account_with_expanded_key = Account::from_libolm_pickle(&pickle, key)?;

        let signing_key_clone = account_with_expanded_key.signing_key.clone();
        signing_key_clone.sign("You met with a terrible fate, haven’t you?".as_bytes());
        account_with_expanded_key.sign("You met with a terrible fate, haven’t you?");

        Ok(())
    }

    #[test]
    fn invalid_session_creation_does_not_remove_otk() -> Result<()> {
        let mut alice = Account::new();
        let malory = Account::new();
        alice.generate_one_time_keys(1);

        let mut session = malory.create_outbound_session(
            *alice.curve25519_key(),
            *alice.one_time_keys().values().next().expect("Should have one-time key"),
        );

        let message = session.encrypt("Test");

        if let OlmMessage::PreKey(m) = message {
            let mut message = base64_decode(m.inner)?;
            let message_len = message.len();

            // We mangle the MAC so decryption fails but creating a Session
            // succeeds.
            message[message_len - Mac::TRUNCATED_LEN..message_len]
                .copy_from_slice(&[0u8; Mac::TRUNCATED_LEN]);

            let message = base64_encode(message);
            let message = PreKeyMessage { inner: message };

            match alice.create_inbound_session(malory.curve25519_key(), &message) {
                Err(SessionCreationError::Decryption(_)) => {}
                e => bail!("Expected a decryption error, got {:?}", e),
            }
            assert!(
                !alice.one_time_keys.private_keys.is_empty()
                    && !alice.one_time_keys.private_keys.is_empty(),
                "The one-time key was removed when it shouldn't"
            );

            Ok(())
        } else {
            bail!("Invalid message type");
        }
    }
}
