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

use std::collections::HashMap;

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::ReusableSecret;
use zeroize::Zeroize;

use self::{
    fallback_keys::FallbackKeys,
    one_time_keys::{OneTimeKeys, OneTimeKeysPickle},
};
use super::{
    messages::PreKeyMessage,
    session::{DecryptionError, Session},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
};
use crate::{
    types::{
        Curve25519Keypair, Curve25519KeypairPickle, Curve25519PublicKey, Curve25519SecretKey,
        Ed25519Keypair, Ed25519KeypairPickle, Ed25519PublicKey, KeyId,
    },
    utilities::{pickle, unpickle, DecodeSecret},
    Ed25519Signature, PickleError,
};

const PUBLIC_MAX_ONE_TIME_KEYS: usize = 50;

/// Error describing failure modes when creating a Olm Session from an incoming
/// Olm message.
#[derive(Error, Debug)]
pub enum SessionCreationError {
    /// The pre-key message contained an unknown one-time key. This happens
    /// either because we never had such a one-time key, or because it has
    /// already been used up.
    #[error("The pre-key message contained an unknown one-time key")]
    MissingOneTimeKey,
    /// The pre-key message contains a curve25519 identity key that doesn't
    /// match to the identity key that was given.
    #[error("The given identity key doesn't match the one in the pre-key message")]
    MismatchedIdentityKey,
    /// The pre-key message that was used to establish the Session couldn't be
    /// decrypted. The message needs to be decryptable, otherwise we will have
    /// created a Session that wasn't used to encrypt the pre-key message.
    #[error("The message that was used to establish the Session couldn't be decrypted")]
    Decryption(#[from] DecryptionError),
}

/// Struct holding the two public identity keys of an [`Account`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct IdentityKeys {
    /// The ed25519 key, used for signing.
    pub ed25519: Ed25519PublicKey,
    /// The curve25519 key, used for to establish shared secrets.
    pub curve25519: Curve25519PublicKey,
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
            one_time_keys: OneTimeKeys::new(),
            fallback_keys: FallbackKeys::new(),
        }
    }

    /// Get the IdentityKeys of this Account
    pub fn identity_keys(&self) -> IdentityKeys {
        IdentityKeys { ed25519: self.ed25519_key(), curve25519: *self.curve25519_key() }
    }

    /// Get a reference to the account's public Ed25519 key
    pub fn ed25519_key(&self) -> Ed25519PublicKey {
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
    pub fn sign(&self, message: &str) -> Ed25519Signature {
        self.signing_key.sign(message.as_bytes())
    }

    /// Get the maximum number of one-time keys the client should keep on the
    /// server.
    ///
    /// **Note**: this differs from the libolm method of the same name, the
    /// libolm method returned the maximum amount of one-time keys the `Account`
    /// could hold and only half of those should be uploaded.
    pub fn max_number_of_one_time_keys(&self) -> usize {
        // We tell clients to upload a limited amount of one-time keys, this
        // amount is smaller than what we can store.
        //
        // We do this because a client might receive the count of uploaded keys
        // from the server before they receive all the pre-key messages that
        // used some of our one-time keys. This would mean that we would forget
        // private one-time keys, since we're generating new ones, while we
        // didn't yet receive the pre-key messages that used those one-time
        // keys.
        PUBLIC_MAX_ONE_TIME_KEYS
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

    /// Remove a one-time key that has previously been published but not yet
    /// used.
    ///
    /// **Note**: This function is only rarely useful and you'll know if you
    /// need it. Notably, you do *not* need to call it manually when using up
    /// a key via [`Account::create_inbound_session`] since the key is
    /// automatically removed in that case.
    pub fn remove_one_time_key(
        &mut self,
        public_key: &Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.one_time_keys.remove_secret_key(public_key)
    }

    /// Create a [`Session`] from the given pre-key message and identity key
    pub fn create_inbound_session(
        &mut self,
        their_identity_key: &Curve25519PublicKey,
        pre_key_message: &PreKeyMessage,
    ) -> Result<InboundCreationResult, SessionCreationError> {
        if their_identity_key != &pre_key_message.identity_key() {
            Err(SessionCreationError::MismatchedIdentityKey)
        } else {
            // Find the matching private key that the message claims to have
            // used to create the Session that encrypted it.
            let one_time_key = self
                .find_one_time_key(&pre_key_message.one_time_key())
                .ok_or(SessionCreationError::MissingOneTimeKey)?;

            // Construct a 3DH shared secret from the various curve25519 keys.
            let shared_secret = RemoteShared3DHSecret::new(
                self.diffie_hellman_key.secret_key(),
                one_time_key,
                &pre_key_message.identity_key(),
                &pre_key_message.base_key(),
            );

            // These will be used to uniquely identify the Session.
            let session_keys = SessionKeys {
                identity_key: pre_key_message.identity_key(),
                base_key: pre_key_message.base_key(),
                one_time_key: pre_key_message.one_time_key(),
            };

            // Create a Session, AKA a double ratchet, this one will have an
            // inactive sending chain until we decide to encrypt a message.
            let mut session = Session::new_remote(
                shared_secret,
                pre_key_message.message.ratchet_key,
                session_keys,
            );

            // Decrypt the message to check if the Session is actually valid.
            let plaintext = session.decrypt_decoded(&pre_key_message.message)?;
            let plaintext = String::from_utf8_lossy(&plaintext).to_string();

            // We only drop the one-time key now, this is why we can't use a
            // one-time key type that takes `self`. If we didn't do this,
            // someone could maliciously pretend to use up our one-time key and
            // make us drop the private part. Unsuspecting users that actually
            // try to use such an one-time key won't be able to commnuicate with
            // us. This is strictly worse than the one-time key exhaustion
            // scenario.
            self.remove_one_time_key(&pre_key_message.one_time_key());

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
        self.one_time_keys
            .unpublished_public_keys
            .iter()
            .map(|(key_id, key)| (*key_id, *key))
            .collect()
    }

    /// Get the currently unpublished one-time keys in base64-encoded form.
    ///
    /// The one-time keys should be published to a server and marked as
    /// published using the `mark_keys_as_published()` method.
    pub fn one_time_keys_encoded(&self) -> HashMap<String, String> {
        self.one_time_keys
            .unpublished_public_keys
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
    pub fn fallback_key(&self) -> HashMap<KeyId, Curve25519PublicKey> {
        let fallback_key = self.fallback_keys.unpublished_fallback_key();

        if let Some(fallback_key) = fallback_key {
            HashMap::from([(fallback_key.key_id(), fallback_key.public_key())])
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

    /// Restore an [`Account`] from a previously saved [`AccountPickle`].
    pub fn from_pickle(pickle: AccountPickle) -> Self {
        pickle.into()
    }

    /// Create an [`Account`] object by unpickling an account pickle in libolm
    /// legacy pickle format.
    ///
    /// Such pickles are encrypted and need to first be decrypted using
    /// `pickle_key`.
    #[cfg(feature = "libolm-compat")]
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &str,
    ) -> Result<Self, crate::LibolmPickleError> {
        use self::fallback_keys::FallbackKey;
        use crate::utilities::{unpickle_libolm, Decode};

        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        struct OneTimeKey {
            key_id: u32,
            published: bool,
            public_key: [u8; 32],
            private_key: Box<[u8; 32]>,
        }

        impl Decode for OneTimeKey {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                let key_id = u32::decode(reader)?;
                let published = bool::decode(reader)?;
                let public_key = <[u8; 32]>::decode(reader)?;
                let private_key = <[u8; 32]>::decode_secret(reader)?;

                Ok(Self { key_id, published, public_key, private_key })
            }
        }

        impl From<&OneTimeKey> for FallbackKey {
            fn from(key: &OneTimeKey) -> Self {
                FallbackKey {
                    key_id: KeyId(key.key_id.into()),
                    key: Curve25519SecretKey::from_slice(&key.private_key),
                    published: key.published,
                }
            }
        }

        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        struct FallbackKeysArray {
            fallback_key: Option<OneTimeKey>,
            previous_fallback_key: Option<OneTimeKey>,
        }

        impl Decode for FallbackKeysArray {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                let count = u8::decode(reader)?;

                let (fallback_key, previous_fallback_key) = if count >= 1 {
                    let fallback_key = OneTimeKey::decode(reader)?;

                    let previous_fallback_key =
                        if count >= 2 { Some(OneTimeKey::decode(reader)?) } else { None };

                    (Some(fallback_key), previous_fallback_key)
                } else {
                    (None, None)
                };

                Ok(Self { fallback_key, previous_fallback_key })
            }
        }

        #[derive(Debug, Zeroize)]
        #[zeroize(drop)]
        struct Pickle {
            version: u32,
            public_ed25519_key: [u8; 32],
            private_ed25519_key: Box<[u8; 64]>,
            public_curve25519_key: [u8; 32],
            private_curve25519_key: Box<[u8; 32]>,
            one_time_keys: Vec<OneTimeKey>,
            fallback_keys: FallbackKeysArray,
        }

        impl Decode for Pickle {
            fn decode(
                reader: &mut impl std::io::Read,
            ) -> Result<Self, crate::utilities::LibolmDecodeError> {
                let version = u32::decode(reader)?;

                let public_ed25519_key = <[u8; 32]>::decode(reader)?;
                let private_ed25519_key = <[u8; 64]>::decode_secret(reader)?;

                let public_curve25519_key = <[u8; 32]>::decode(reader)?;
                let private_curve25519_key = <[u8; 32]>::decode_secret(reader)?;
                let one_time_keys = Vec::decode(reader)?;
                let fallback_keys = FallbackKeysArray::decode(reader)?;

                Ok(Self {
                    version,
                    public_ed25519_key,
                    private_ed25519_key,
                    public_curve25519_key,
                    private_curve25519_key,
                    one_time_keys,
                    fallback_keys,
                })
            }
        }

        impl TryFrom<Pickle> for Account {
            type Error = crate::LibolmPickleError;

            fn try_from(pickle: Pickle) -> Result<Self, Self::Error> {
                let mut one_time_keys = OneTimeKeys::new();
                let mut max_key_id = 0;

                for key in &pickle.one_time_keys {
                    let secret_key = Curve25519SecretKey::from_slice(&key.private_key);
                    let key_id = KeyId(key.key_id.into());
                    one_time_keys.insert_secret_key(key_id, secret_key, key.published);

                    if key_id.0 > max_key_id {
                        max_key_id = key_id.0;
                    }
                }

                // If there are no one-time keys in the pickle our key id will be 0,
                // otherwise we'll have to use the max found key id and increment
                // it.
                one_time_keys.key_id =
                    if pickle.one_time_keys.is_empty() { 0 } else { max_key_id + 1 };

                let fallback_keys = FallbackKeys {
                    key_id: pickle
                        .fallback_keys
                        .fallback_key
                        .as_ref()
                        .map(|k| k.key_id + 1)
                        .unwrap_or(0) as u64,
                    fallback_key: pickle.fallback_keys.fallback_key.as_ref().map(|k| k.into()),
                    previous_fallback_key: pickle
                        .fallback_keys
                        .previous_fallback_key
                        .as_ref()
                        .map(|k| k.into()),
                };

                Ok(Self {
                    signing_key: Ed25519Keypair::from_expanded_key(&pickle.private_ed25519_key)?,
                    diffie_hellman_key: Curve25519Keypair::from_secret_key(
                        &pickle.private_curve25519_key,
                    ),
                    one_time_keys,
                    fallback_keys,
                })
            }
        }

        const PICKLE_VERSION: u32 = 4;
        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
    }
}

impl Default for Account {
    fn default() -> Self {
        Self::new()
    }
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`Account::pickle`].
#[derive(Serialize, Deserialize)]
pub struct AccountPickle {
    signing_key: Ed25519KeypairPickle,
    diffie_hellman_key: Curve25519KeypairPickle,
    one_time_keys: OneTimeKeysPickle,
    fallback_keys: FallbackKeys,
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`Account::pickle`].
impl AccountPickle {
    /// Serialize and encrypt the pickle using the given key.
    ///
    /// This is the inverse of [`AccountPickle::from_encrypted`].
    pub fn encrypt(self, pickle_key: &[u8; 32]) -> String {
        pickle(&self, pickle_key)
    }

    /// Obtain a pickle from a ciphertext by decrypting and deserializing using
    /// the given key.
    ///
    /// This is the inverse of [`AccountPickle::encrypt`].
    pub fn from_encrypted(ciphertext: &str, pickle_key: &[u8; 32]) -> Result<Self, PickleError> {
        unpickle(ciphertext, pickle_key)
    }
}

impl From<AccountPickle> for Account {
    fn from(pickle: AccountPickle) -> Self {
        Self {
            signing_key: pickle.signing_key.into(),
            diffie_hellman_key: pickle.diffie_hellman_key.into(),
            one_time_keys: pickle.one_time_keys.into(),
            fallback_keys: pickle.fallback_keys,
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::{bail, Context, Result};
    use olm_rs::{account::OlmAccount, session::OlmMessage as LibolmOlmMessage};

    use super::{Account, InboundCreationResult, SessionCreationError};
    use crate::{
        cipher::Mac,
        olm::{
            messages::{OlmMessage, PreKeyMessage},
            AccountPickle,
        },
        Curve25519PublicKey as PublicKey,
    };

    const PICKLE_KEY: [u8; 32] = [0u8; 32];

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
            .next()
            .cloned()
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
        let olm_message = alice_session.encrypt(message);

        if let OlmMessage::PreKey(m) = olm_message {
            assert_eq!(m.session_keys(), alice_session.session_keys());

            let InboundCreationResult { session: mut bob_session, plaintext } =
                bob.create_inbound_session(alice.curve25519_key(), &m)?;
            assert_eq!(alice_session.session_id(), bob_session.session_id());
            assert_eq!(m.session_keys(), bob_session.session_keys());

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
            .next()
            .cloned()
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
            bob.fallback_key().values().next().cloned().expect("Didn't find a valid fallback key");
        assert!(bob.one_time_keys.private_keys.is_empty());

        let alice_session = alice
            .create_outbound_session(bob.curve25519_key_encoded(), &one_time_key.to_base64())?;

        let text = "It's a secret to everybody";

        let message = alice_session.encrypt(text).into();
        let identity_key = PublicKey::from_base64(alice.parsed_identity_keys().curve25519())?;

        if let OlmMessage::PreKey(m) = &message {
            let InboundCreationResult { session, plaintext } =
                bob.create_inbound_session(&identity_key, m)?;

            assert_eq!(m.session_keys(), session.session_keys());
            assert_eq!(alice_session.session_id(), session.session_id());
            assert!(bob.fallback_keys.fallback_key.is_some());

            assert_eq!(text, plaintext);
        } else {
            bail!("Got invalid message type from olm_rs");
        };

        Ok(())
    }

    #[test]
    fn account_pickling_roundtrip_is_identity() -> Result<()> {
        let mut account = Account::new();

        account.generate_one_time_keys(50);

        // Generate two fallback keys so the previous fallback key field gets populated.
        account.generate_fallback_key();
        account.generate_fallback_key();

        let pickle = account.pickle().encrypt(&PICKLE_KEY);

        let decrypted_pickle = AccountPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let unpickled_account = Account::from_pickle(decrypted_pickle);
        let repickle = unpickled_account.pickle();

        assert_eq!(account.identity_keys(), unpickled_account.identity_keys());

        let decrypted_pickle = AccountPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let pickle = serde_json::to_value(decrypted_pickle)?;
        let repickle = serde_json::to_value(repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn libolm_unpickling() -> Result<()> {
        let olm = OlmAccount::new();
        olm.generate_one_time_keys(10);
        olm.generate_fallback_key();

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

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
            unpickled
                .fallback_key()
                .values()
                .next()
                .expect("We should have a fallback key")
                .to_base64()
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn signing_with_expanded_key() -> Result<()> {
        let olm = OlmAccount::new();
        olm.generate_one_time_keys(10);
        olm.generate_fallback_key();

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

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
            let mut message = m.to_bytes();
            let message_len = message.len();

            // We mangle the MAC so decryption fails but creating a Session
            // succeeds.
            message[message_len - Mac::TRUNCATED_LEN..message_len]
                .copy_from_slice(&[0u8; Mac::TRUNCATED_LEN]);

            let message = PreKeyMessage::try_from(message)?;

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
