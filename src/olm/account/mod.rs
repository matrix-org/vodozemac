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

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::ReusableSecret;
use zeroize::Zeroize;

pub use self::one_time_keys::OneTimeKeyGenerationResult;
use self::{
    fallback_keys::FallbackKeys,
    one_time_keys::{OneTimeKeys, OneTimeKeysPickle},
};
use super::{
    messages::PreKeyMessage,
    session::{DecryptionError, Session},
    session_keys::SessionKeys,
    shared_secret::{RemoteShared3DHSecret, Shared3DHSecret},
    SessionConfig,
};
use crate::{
    types::{
        Curve25519Keypair, Curve25519KeypairPickle, Curve25519PublicKey, Curve25519SecretKey,
        Ed25519Keypair, Ed25519KeypairPickle, Ed25519PublicKey, KeyId,
    },
    utilities::{pickle, unpickle},
    Ed25519Signature, PickleError,
};

const PUBLIC_MAX_ONE_TIME_KEYS: usize = 50;

/// Error describing failure modes when creating a Olm [`Session`] from an
/// incoming Olm message.
#[derive(Error, Debug)]
pub enum SessionCreationError {
    /// The pre-key message contained an unknown one-time key. This happens
    /// either because we never had such a one-time key, or because it has
    /// already been used up.
    #[error("The pre-key message contained an unknown one-time key: {0}")]
    MissingOneTimeKey(Curve25519PublicKey),
    /// The pre-key message contains a Curve25519 identity key that doesn't
    /// match to the identity key that was given.
    #[error(
        "The given identity key doesn't match the one in the pre-key message: \
        expected {0}, got {1}"
    )]
    MismatchedIdentityKey(Curve25519PublicKey, Curve25519PublicKey),
    /// The pre-key message that was used to establish the [`Session`] couldn't
    /// be decrypted. The message needs to be decryptable, otherwise we will
    /// have created a Session that wasn't used to encrypt the pre-key
    /// message.
    #[error("The message that was used to establish the Session couldn't be decrypted")]
    Decryption(#[from] DecryptionError),
}

/// Struct holding the two public identity keys of an [`Account`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKeys {
    /// The Ed25519 key, used for signing.
    pub ed25519: Ed25519PublicKey,
    /// The Curve25519 key, used for to establish shared secrets.
    pub curve25519: Curve25519PublicKey,
}

/// Return type for the creation of inbound [`Session`] objects.
#[derive(Debug)]
pub struct InboundCreationResult {
    /// The [`Session`] that was created from a pre-key message.
    pub session: Session,
    /// The plaintext of the pre-key message.
    pub plaintext: Vec<u8>,
}

/// Return type for the creation of a dehydrated device.
#[derive(Debug)]
pub struct DehydratedDeviceResult {
    /// The encrypted dehydrated device, as a base64-encoded string.
    pub ciphertext: String,
    /// The nonce used for encrypting, as a base64-encoded string.
    pub nonce: String,
}

/// An Olm [`Account`] manages all cryptographic keys used on a device.
pub struct Account {
    /// A permanent Ed25519 key used for signing. Also known as the fingerprint
    /// key.
    signing_key: Ed25519Keypair,
    /// The permanent Curve25519 key used for triple Diffie-Hellman (3DH). Also
    /// known as the sender key or the identity key.
    diffie_hellman_key: Curve25519Keypair,
    /// The ephemeral (one-time) Curve25519 keys used as part of the triple
    /// Diffie-Hellman (3DH).
    one_time_keys: OneTimeKeys,
    /// The ephemeral Curve25519 keys used in lieu of a one-time key as part of
    /// the 3DH, in case we run out of those. We keep track of both the current
    /// and the previous fallback key in any given moment.
    fallback_keys: FallbackKeys,
}

impl Account {
    /// Create a new [`Account`] with new random identity keys.
    pub fn new() -> Self {
        Self {
            signing_key: Ed25519Keypair::new(),
            diffie_hellman_key: Curve25519Keypair::new(),
            one_time_keys: OneTimeKeys::new(),
            fallback_keys: FallbackKeys::new(),
        }
    }

    /// Get the [`IdentityKeys`] of this Account
    pub const fn identity_keys(&self) -> IdentityKeys {
        IdentityKeys { ed25519: self.ed25519_key(), curve25519: self.curve25519_key() }
    }

    /// Get a copy of the account's public Ed25519 key
    pub const fn ed25519_key(&self) -> Ed25519PublicKey {
        self.signing_key.public_key()
    }

    /// Get a copy of the account's public Curve25519 key
    pub const fn curve25519_key(&self) -> Curve25519PublicKey {
        self.diffie_hellman_key.public_key()
    }

    /// Sign the given message using our Ed25519 fingerprint key.
    pub fn sign(&self, message: impl AsRef<[u8]>) -> Ed25519Signature {
        self.signing_key.sign(message.as_ref())
    }

    /// Get the maximum number of one-time keys the client should keep on the
    /// server.
    ///
    /// **Note**: this differs from the libolm method of the same name, the
    /// libolm method returned the maximum amount of one-time keys the
    /// [`Account`] could hold and only half of those should be uploaded.
    pub const fn max_number_of_one_time_keys(&self) -> usize {
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

    /// Create a [`Session`] with the given identity key and one-time key.
    pub fn create_outbound_session(
        &self,
        session_config: SessionConfig,
        identity_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Session {
        let rng = thread_rng();

        let base_key = ReusableSecret::random_from_rng(rng);
        let public_base_key = Curve25519PublicKey::from(&base_key);

        let shared_secret = Shared3DHSecret::new(
            self.diffie_hellman_key.secret_key(),
            &base_key,
            &identity_key,
            &one_time_key,
        );

        let session_keys = SessionKeys {
            identity_key: self.curve25519_key(),
            base_key: public_base_key,
            one_time_key,
        };

        Session::new(session_config, shared_secret, session_keys)
    }

    /// Try to find a [`Curve25519SecretKey`] that forms a pair with the given
    /// [`Curve25519PublicKey`].
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
    #[cfg(feature = "low-level-api")]
    pub fn remove_one_time_key(
        &mut self,
        public_key: Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.remove_one_time_key_helper(public_key)
    }

    fn remove_one_time_key_helper(
        &mut self,
        public_key: Curve25519PublicKey,
    ) -> Option<Curve25519SecretKey> {
        self.one_time_keys.remove_secret_key(&public_key)
    }

    /// Create a [`Session`] from the given [`PreKeyMessage`] message and
    /// identity key
    pub fn create_inbound_session(
        &mut self,
        their_identity_key: Curve25519PublicKey,
        pre_key_message: &PreKeyMessage,
    ) -> Result<InboundCreationResult, SessionCreationError> {
        if their_identity_key != pre_key_message.identity_key() {
            Err(SessionCreationError::MismatchedIdentityKey(
                their_identity_key,
                pre_key_message.identity_key(),
            ))
        } else {
            // Find the matching private part of the OTK that the message claims
            // was used to create the session that encrypted it.
            let public_otk = pre_key_message.one_time_key();
            let private_otk = self
                .find_one_time_key(&public_otk)
                .ok_or(SessionCreationError::MissingOneTimeKey(public_otk))?;

            // Construct a 3DH shared secret from the various curve25519 keys.
            let shared_secret = RemoteShared3DHSecret::new(
                self.diffie_hellman_key.secret_key(),
                private_otk,
                &pre_key_message.identity_key(),
                &pre_key_message.base_key(),
            );

            // These will be used to uniquely identify the Session.
            let session_keys = SessionKeys {
                identity_key: pre_key_message.identity_key(),
                base_key: pre_key_message.base_key(),
                one_time_key: pre_key_message.one_time_key(),
            };

            let config = if pre_key_message.message.mac_truncated() {
                SessionConfig::version_1()
            } else {
                SessionConfig::version_2()
            };

            // Create a Session, AKA a double ratchet, this one will have an
            // inactive sending chain until we decide to encrypt a message.
            let mut session = Session::new_remote(
                config,
                shared_secret,
                pre_key_message.message.ratchet_key,
                session_keys,
            );

            // Decrypt the message to check if the Session is actually valid.
            let plaintext = session.decrypt_decoded(&pre_key_message.message)?;

            // We only drop the one-time key now, this is why we can't use a
            // one-time key type that takes `self`. If we didn't do this,
            // someone could maliciously pretend to use up our one-time key and
            // make us drop the private part. Unsuspecting users that actually
            // try to use such an one-time key won't be able to commnuicate with
            // us. This is strictly worse than the one-time key exhaustion
            // scenario.
            self.remove_one_time_key_helper(pre_key_message.one_time_key());

            Ok(InboundCreationResult { session, plaintext })
        }
    }

    /// Generates the supplied number of one time keys.
    /// Returns the public parts of the one-time keys that were created and
    /// discarded.
    ///
    /// Our one-time key store inside the [`Account`] has a limited amount of
    /// places for one-time keys, If we try to generate new ones while the store
    /// is completely populated, the oldest one-time keys will get discarded
    /// to make place for new ones.
    pub fn generate_one_time_keys(&mut self, count: usize) -> OneTimeKeyGenerationResult {
        self.one_time_keys.generate(count)
    }

    /// Get the number of one-time keys we have stored locally.
    ///
    /// This will be equal or greater to the number of one-time keys we have
    /// published. Each time a new [`Session`] is created using the
    /// [`Account::create_inbound_session()`] a one-time key will be used up
    /// and removed.
    pub fn stored_one_time_key_count(&self) -> usize {
        self.one_time_keys.private_keys.len()
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

    /// Generate a single new fallback key.
    ///
    /// The fallback key will be used by other users to establish a [`Session`]
    /// if all the one-time keys on the server have been used up.
    ///
    /// Returns the public Curve25519 key of the *previous* fallback key, that
    /// is, the one that will get removed from the [`Account`] when this method
    /// is called. This return value is mostly useful for logging purposes.
    pub fn generate_fallback_key(&mut self) -> Option<Curve25519PublicKey> {
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

    /// The [`Account`] stores at most two private parts of the fallback key.
    /// This method lets us forget the previously used fallback key.
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
        pickle_key: &[u8],
    ) -> Result<Self, crate::LibolmPickleError> {
        use self::libolm::Pickle;
        use crate::utilities::unpickle_libolm;

        const PICKLE_VERSION: u32 = 4;
        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
    }

    /// Pickle an [`Account`] into a libolm pickle format.
    ///
    /// This pickle can be restored using the [`Account::from_libolm_pickle()`]
    /// method, or can be used in the [`libolm`] C library.
    ///
    /// The pickle will be encrypted using the pickle key.
    ///
    /// *Note*: This method might be lossy, the vodozemac [`Account`] has the
    /// ability to hold more one-time keys compared to the [`libolm`]
    /// variant.
    ///
    /// ⚠️  ***Security Warning***: The pickle key will get expanded into both
    /// an AES key and an IV in a deterministic manner. If the same pickle
    /// key is reused, this will lead to IV reuse. To prevent this, users
    /// have to ensure that they always use a globally (probabilistically)
    /// unique pickle key.
    ///
    /// [`libolm`]: https://gitlab.matrix.org/matrix-org/olm/
    ///
    /// # Examples
    /// ```
    /// use vodozemac::olm::Account;
    /// use olm_rs::{account::OlmAccount, PicklingMode};
    /// let account = Account::new();
    ///
    /// let export = account
    ///     .to_libolm_pickle(&[0u8; 32])
    ///     .expect("We should be able to pickle a freshly created Account");
    ///
    /// let unpickled = OlmAccount::unpickle(
    ///     export,
    ///     PicklingMode::Encrypted { key: [0u8; 32].to_vec() },
    /// ).expect("We should be able to unpickle our exported Account");
    /// ```
    #[cfg(feature = "libolm-compat")]
    pub fn to_libolm_pickle(&self, pickle_key: &[u8]) -> Result<String, crate::LibolmPickleError> {
        use self::libolm::Pickle;
        use crate::utilities::pickle_libolm;
        pickle_libolm::<Pickle>(self.into(), pickle_key)
    }

    #[cfg(all(any(fuzzing, test), feature = "libolm-compat"))]
    #[doc(hidden)]
    pub fn from_decrypted_libolm_pickle(pickle: &[u8]) -> Result<Self, crate::LibolmPickleError> {
        use std::io::Cursor;

        use matrix_pickle::Decode;

        use self::libolm::Pickle;

        let mut cursor = Cursor::new(&pickle);
        let pickle = Pickle::decode(&mut cursor)?;

        pickle.try_into()
    }

    /// Create a dehydrated device from the account.
    ///
    /// A dehydrated device is a device that is stored encrypted on the server
    /// that can receive messages when the user has no other active devices.
    /// Upon login, the user can rehydrate the device (using
    /// [`from_dehydrated_device`]) and decrypt the messages sent to the
    /// dehydrated device.
    ///
    /// The account must be a newly-created account that does not have any Olm
    /// sessions, since the dehydrated device format does not store sessions.
    ///
    /// Returns the ciphertext and nonce.  `key` is a 256-bit (32-byte) key for
    /// encrypting the device.
    ///
    /// The format used here is defined in
    /// [MSC3814](https://github.com/matrix-org/matrix-spec-proposals/pull/3814).
    pub fn to_dehydrated_device(
        &self,
        key: &[u8; 32],
    ) -> Result<DehydratedDeviceResult, crate::DehydratedDeviceError> {
        use matrix_pickle::Encode;

        use self::dehydrated_device::Pickle;
        use crate::{utilities::base64_encode, DehydratedDeviceError, LibolmPickleError};

        let pickle: Pickle = self.into();
        let mut encoded = pickle
            .encode_to_vec()
            .map_err(|e| DehydratedDeviceError::LibolmPickle(LibolmPickleError::Encode(e)))?;
        let cipher = ChaCha20Poly1305::new(key.into());
        let rng = thread_rng();
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let ciphertext = cipher.encrypt(&nonce, encoded.as_slice());
        encoded.zeroize();
        let ciphertext = ciphertext?;

        Ok(DehydratedDeviceResult {
            ciphertext: base64_encode(ciphertext),
            nonce: base64_encode(nonce),
        })
    }

    /// Create an [`Account`] object from a dehydrated device.
    ///
    /// `ciphertext` and `nonce` are the ciphertext and nonce returned by
    /// [`to_dehydrated_device`]. `key` is a 256-bit (32-byte) key for
    /// decrypting the device, and must be the same key used when
    /// [`to_dehydrate_device`] was called.
    pub fn from_dehydrated_device(
        ciphertext: &str,
        nonce: &str,
        key: &[u8; 32],
    ) -> Result<Self, crate::DehydratedDeviceError> {
        use self::dehydrated_device::PICKLE_VERSION;
        use crate::utilities::{base64_decode, get_pickle_version};

        let cipher = ChaCha20Poly1305::new(key.into());
        let ciphertext = base64_decode(ciphertext)?;
        let nonce = base64_decode(nonce)?;
        if nonce.len() != 12 {
            return Err(crate::DehydratedDeviceError::InvalidNonce);
        }
        let mut plaintext = cipher.decrypt(nonce.as_slice().into(), ciphertext.as_slice())?;
        let version =
            get_pickle_version(&plaintext).ok_or(crate::DehydratedDeviceError::MissingVersion)?;
        if version != PICKLE_VERSION {
            return Err(crate::DehydratedDeviceError::Version(PICKLE_VERSION, version));
        }

        let pickle = Self::from_decrypted_dehydrated_device(&plaintext);
        plaintext.zeroize();
        pickle
    }

    // This function is public for fuzzing, but should not be used by anything
    // else
    #[doc(hidden)]
    pub fn from_decrypted_dehydrated_device(
        pickle: &[u8],
    ) -> Result<Self, crate::DehydratedDeviceError> {
        use std::io::Cursor;

        use matrix_pickle::Decode;

        use self::dehydrated_device::Pickle;
        use crate::{DehydratedDeviceError, LibolmPickleError};

        let mut cursor = Cursor::new(&pickle);
        let pickle = Pickle::decode(&mut cursor)
            .map_err(|e| DehydratedDeviceError::LibolmPickle(LibolmPickleError::Decode(e)))?;

        pickle.try_into()
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

#[cfg(feature = "libolm-compat")]
mod libolm {
    use matrix_pickle::{Decode, DecodeError, Encode, EncodeError};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        fallback_keys::{FallbackKey, FallbackKeys},
        one_time_keys::OneTimeKeys,
        Account,
    };
    use crate::{
        types::{Curve25519Keypair, Curve25519SecretKey},
        utilities::LibolmEd25519Keypair,
        Curve25519PublicKey, Ed25519Keypair, KeyId,
    };

    #[derive(Encode, Decode, Zeroize, ZeroizeOnDrop)]
    struct OneTimeKey {
        key_id: u32,
        published: bool,
        public_key: [u8; 32],
        private_key: Box<[u8; 32]>,
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

    #[derive(Zeroize, ZeroizeOnDrop)]
    struct FallbackKeysArray {
        fallback_key: Option<OneTimeKey>,
        previous_fallback_key: Option<OneTimeKey>,
    }

    impl Decode for FallbackKeysArray {
        fn decode(reader: &mut impl std::io::Read) -> Result<Self, DecodeError> {
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

    impl Encode for FallbackKeysArray {
        fn encode(&self, writer: &mut impl std::io::Write) -> Result<usize, EncodeError> {
            let ret = match (&self.fallback_key, &self.previous_fallback_key) {
                (None, None) => 0u8.encode(writer)?,
                (Some(key), None) | (None, Some(key)) => {
                    let mut ret = 1u8.encode(writer)?;
                    ret += key.encode(writer)?;

                    ret
                }
                (Some(key), Some(previous_key)) => {
                    let mut ret = 2u8.encode(writer)?;
                    ret += key.encode(writer)?;
                    ret += previous_key.encode(writer)?;

                    ret
                }
            };

            Ok(ret)
        }
    }

    #[derive(Encode, Decode, Zeroize, ZeroizeOnDrop)]
    pub(super) struct Pickle {
        version: u32,
        ed25519_keypair: LibolmEd25519Keypair,
        public_curve25519_key: [u8; 32],
        private_curve25519_key: Box<[u8; 32]>,
        one_time_keys: Vec<OneTimeKey>,
        fallback_keys: FallbackKeysArray,
        next_key_id: u32,
    }

    impl TryFrom<&FallbackKey> for OneTimeKey {
        type Error = ();

        fn try_from(key: &FallbackKey) -> Result<Self, ()> {
            Ok(OneTimeKey {
                key_id: key.key_id.0.try_into().map_err(|_| ())?,
                published: key.published(),
                public_key: key.public_key().to_bytes(),
                private_key: key.secret_key().to_bytes(),
            })
        }
    }

    impl From<&Account> for Pickle {
        fn from(account: &Account) -> Self {
            let one_time_keys: Vec<_> = account
                .one_time_keys
                .secret_keys()
                .iter()
                .filter_map(|(key_id, secret_key)| {
                    Some(OneTimeKey {
                        key_id: key_id.0.try_into().ok()?,
                        published: account.one_time_keys.is_secret_key_published(key_id),
                        public_key: Curve25519PublicKey::from(secret_key).to_bytes(),
                        private_key: secret_key.to_bytes(),
                    })
                })
                .collect();

            let fallback_keys = FallbackKeysArray {
                fallback_key: account
                    .fallback_keys
                    .fallback_key
                    .as_ref()
                    .and_then(|f| f.try_into().ok()),
                previous_fallback_key: account
                    .fallback_keys
                    .previous_fallback_key
                    .as_ref()
                    .and_then(|f| f.try_into().ok()),
            };

            let next_key_id = account.one_time_keys.next_key_id.try_into().unwrap_or_default();

            Self {
                version: 4,
                ed25519_keypair: LibolmEd25519Keypair {
                    private_key: account.signing_key.expanded_secret_key(),
                    public_key: account.signing_key.public_key().as_bytes().to_owned(),
                },
                public_curve25519_key: account.diffie_hellman_key.public_key().to_bytes(),
                private_curve25519_key: account.diffie_hellman_key.secret_key().to_bytes(),
                one_time_keys,
                fallback_keys,
                next_key_id,
            }
        }
    }

    impl TryFrom<Pickle> for Account {
        type Error = crate::LibolmPickleError;

        fn try_from(pickle: Pickle) -> Result<Self, Self::Error> {
            let mut one_time_keys = OneTimeKeys::new();

            for key in &pickle.one_time_keys {
                let secret_key = Curve25519SecretKey::from_slice(&key.private_key);
                let key_id = KeyId(key.key_id.into());
                one_time_keys.insert_secret_key(key_id, secret_key, key.published);
            }

            one_time_keys.next_key_id = pickle.next_key_id.into();

            let fallback_keys = FallbackKeys {
                key_id: pickle
                    .fallback_keys
                    .fallback_key
                    .as_ref()
                    .map(|k| k.key_id.wrapping_add(1))
                    .unwrap_or(0) as u64,
                fallback_key: pickle.fallback_keys.fallback_key.as_ref().map(|k| k.into()),
                previous_fallback_key: pickle
                    .fallback_keys
                    .previous_fallback_key
                    .as_ref()
                    .map(|k| k.into()),
            };

            Ok(Self {
                signing_key: Ed25519Keypair::from_expanded_key(
                    &pickle.ed25519_keypair.private_key,
                )?,
                diffie_hellman_key: Curve25519Keypair::from_secret_key(
                    &pickle.private_curve25519_key,
                ),
                one_time_keys,
                fallback_keys,
            })
        }
    }
}

mod dehydrated_device {
    use matrix_pickle::{Decode, DecodeError, Encode, EncodeError};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        fallback_keys::{FallbackKey, FallbackKeys},
        one_time_keys::OneTimeKeys,
        Account,
    };
    use crate::{
        types::{Curve25519Keypair, Curve25519SecretKey},
        DehydratedDeviceError, Ed25519Keypair, KeyId,
    };

    #[derive(Encode, Decode, Zeroize, ZeroizeOnDrop)]
    pub(crate) struct OneTimeKey {
        #[secret]
        pub(crate) private_key: Box<[u8; 32]>,
    }

    impl From<&OneTimeKey> for FallbackKey {
        fn from(key: &OneTimeKey) -> Self {
            FallbackKey {
                key_id: KeyId(0),
                key: Curve25519SecretKey::from_slice(&key.private_key),
                published: true,
            }
        }
    }

    impl TryFrom<&FallbackKey> for OneTimeKey {
        type Error = ();

        fn try_from(key: &FallbackKey) -> Result<Self, ()> {
            Ok(OneTimeKey { private_key: key.secret_key().to_bytes() })
        }
    }

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub(crate) struct OptFallbackKey {
        pub(crate) fallback_key: Option<OneTimeKey>,
    }

    impl Decode for OptFallbackKey {
        fn decode(reader: &mut impl std::io::Read) -> Result<Self, DecodeError> {
            let present = bool::decode(reader)?;

            let fallback_key = if present {
                let fallback_key = OneTimeKey::decode(reader)?;

                Some(fallback_key)
            } else {
                None
            };

            Ok(Self { fallback_key })
        }
    }

    impl Encode for OptFallbackKey {
        fn encode(&self, writer: &mut impl std::io::Write) -> Result<usize, EncodeError> {
            let ret = match &self.fallback_key {
                None => false.encode(writer)?,
                Some(key) => {
                    let mut ret = true.encode(writer)?;
                    ret += key.encode(writer)?;

                    ret
                }
            };

            Ok(ret)
        }
    }

    #[derive(Encode, Decode, Zeroize, ZeroizeOnDrop)]
    /// Pickle used for dehydrated devices.
    ///
    /// Dehydrated devices are used for receiving encrypted messages when the
    /// user has no other devices logged in, and are defined in
    /// [MSC3814](https://github.com/matrix-org/matrix-spec-proposals/pull/3814).
    pub(super) struct Pickle {
        version: u32,
        #[secret]
        private_curve25519_key: Box<[u8; 32]>,
        #[secret]
        private_ed25519_key: Box<[u8; 32]>,
        one_time_keys: Vec<OneTimeKey>,
        opt_fallback_key: OptFallbackKey,
    }

    pub(super) const PICKLE_VERSION: u32 = 1;

    impl From<&Account> for Pickle {
        fn from(account: &Account) -> Self {
            let one_time_keys: Vec<_> = account
                .one_time_keys
                .secret_keys()
                .iter()
                .map(|(_key_id, secret_key)| OneTimeKey { private_key: secret_key.to_bytes() })
                .collect();

            let fallback_key =
                account.fallback_keys.fallback_key.as_ref().and_then(|f| f.try_into().ok());

            Self {
                version: PICKLE_VERSION,
                private_curve25519_key: account.diffie_hellman_key.secret_key().to_bytes(),
                private_ed25519_key: account
                    .signing_key
                    .unexpanded_secret_key()
                    .expect("Cannot dehydrate an account created from a libolm pickle"),
                one_time_keys,
                opt_fallback_key: OptFallbackKey { fallback_key },
            }
        }
    }

    impl TryFrom<Pickle> for Account {
        type Error = DehydratedDeviceError;

        fn try_from(pickle: Pickle) -> Result<Self, Self::Error> {
            use crate::{DehydratedDeviceError, LibolmPickleError};
            let mut one_time_keys = OneTimeKeys::new();

            for (num, key) in pickle.one_time_keys.iter().enumerate() {
                let secret_key = Curve25519SecretKey::from_slice(&key.private_key);
                let key_id = KeyId(num as u64);
                one_time_keys.insert_secret_key(key_id, secret_key, true);
            }
            one_time_keys.next_key_id = pickle.one_time_keys.len().try_into().unwrap_or_default();

            let fallback_keys = FallbackKeys {
                key_id: 1,
                fallback_key: pickle.opt_fallback_key.fallback_key.as_ref().map(|otk| otk.into()),
                previous_fallback_key: None,
            };

            Ok(Self {
                signing_key: Ed25519Keypair::from_unexpanded_key(&pickle.private_ed25519_key)
                    .map_err(|e| {
                        DehydratedDeviceError::LibolmPickle(LibolmPickleError::PublicKey(e))
                    })?,
                diffie_hellman_key: Curve25519Keypair::from_secret_key(
                    &pickle.private_curve25519_key,
                ),
                one_time_keys,
                fallback_keys,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::{bail, Context, Result};
    use assert_matches::assert_matches;
    use matrix_pickle::{Decode, Encode};
    use olm_rs::{account::OlmAccount, session::OlmMessage as LibolmOlmMessage};

    #[cfg(feature = "libolm-compat")]
    use super::libolm::Pickle;
    use super::{
        dehydrated_device, Account, InboundCreationResult, SessionConfig, SessionCreationError,
    };
    use crate::{
        cipher::Mac,
        olm::{
            account::PUBLIC_MAX_ONE_TIME_KEYS,
            messages::{OlmMessage, PreKeyMessage},
            AccountPickle,
        },
        Curve25519PublicKey as PublicKey,
    };

    const PICKLE_KEY: [u8; 32] = [0u8; 32];

    #[test]
    fn max_number_of_one_time_keys_matches_global_constant() {
        assert_eq!(Account::new().max_number_of_one_time_keys(), PUBLIC_MAX_ONE_TIME_KEYS);
    }

    #[test]
    #[cfg(feature = "low-level-api")]
    fn generate_and_remove_one_time_key() {
        let mut alice = Account::new();
        assert_eq!(alice.stored_one_time_key_count(), 0);

        alice.generate_one_time_keys(1);
        assert_eq!(alice.stored_one_time_key_count(), 1);

        let public_key = alice
            .one_time_keys()
            .values()
            .next()
            .copied()
            .expect("Should have an unpublished one-time key");
        let secret_key_bytes = alice
            .find_one_time_key(&public_key)
            .expect("Should find secret key for public one-time key")
            .to_bytes();
        let removed_key_bytes = alice
            .remove_one_time_key(public_key)
            .expect("Should be able to remove one-time key")
            .to_bytes();

        assert_eq!(removed_key_bytes, secret_key_bytes);
        assert_eq!(alice.stored_one_time_key_count(), 0);
    }

    #[test]
    fn generate_and_forget_fallback_keys() {
        let mut alice = Account::default();
        assert!(!alice.forget_fallback_key());
        alice.generate_fallback_key();
        assert!(!alice.forget_fallback_key());
        alice.generate_fallback_key();
        assert!(alice.forget_fallback_key());
    }

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
        let mut alice_session =
            alice.create_outbound_session(SessionConfig::version_1(), curve25519_key, one_time_key);

        let message = "It's a secret to everybody";
        let olm_message: LibolmOlmMessage = alice_session.encrypt(message).into();

        if let LibolmOlmMessage::PreKey(m) = olm_message.clone() {
            let libolm_session =
                bob.create_inbound_session_from(&alice.curve25519_key().to_base64(), m)?;
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

            assert_eq!(plaintext, reply_plain.as_bytes());

            let another_reply = "Last one";
            let reply = libolm_session.encrypt(another_reply).into();
            let plaintext = alice_session.decrypt(&reply)?;
            assert_eq!(plaintext, another_reply.as_bytes());

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
            SessionConfig::version_2(),
            bob.curve25519_key(),
            *bob.one_time_keys()
                .iter()
                .next()
                .context("Failed getting bob's OTK, which should never happen here.")?
                .1,
        );

        assert!(!bob.one_time_keys().is_empty());
        bob.mark_keys_as_published();
        assert!(bob.one_time_keys().is_empty());

        let message = "It's a secret to everybody";
        let olm_message = alice_session.encrypt(message);

        if let OlmMessage::PreKey(m) = olm_message {
            assert_eq!(m.session_keys(), alice_session.session_keys());
            assert_eq!(m.session_id(), alice_session.session_id());

            let InboundCreationResult { session: mut bob_session, plaintext } =
                bob.create_inbound_session(alice.curve25519_key(), &m)?;
            assert_eq!(alice_session.session_id(), bob_session.session_id());
            assert_eq!(m.session_keys(), bob_session.session_keys());

            assert_eq!(message.as_bytes(), plaintext);

            let second_text = "Here's another secret to everybody";
            let olm_message = alice_session.encrypt(second_text);

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(second_text.as_bytes(), plaintext);

            let reply_plain = "Yes, take this, it's dangerous out there";
            let reply = bob_session.encrypt(reply_plain);
            let plaintext = alice_session.decrypt(&reply)?;

            assert_eq!(plaintext, reply_plain.as_bytes());

            let another_reply = "Last one";
            let reply = bob_session.encrypt(another_reply);
            let plaintext = alice_session.decrypt(&reply)?;
            assert_eq!(plaintext, another_reply.as_bytes());

            let last_text = "Nope, I'll have the last word";
            let olm_message = alice_session.encrypt(last_text);

            let plaintext = bob_session.decrypt(&olm_message)?;
            assert_eq!(last_text.as_bytes(), plaintext);
        }

        Ok(())
    }

    #[test]
    fn inbound_session_creation() -> Result<()> {
        let alice = OlmAccount::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);

        let one_time_key =
            bob.one_time_keys().values().next().cloned().expect("Didn't find a valid one-time key");

        let alice_session = alice.create_outbound_session(
            &bob.curve25519_key().to_base64(),
            &one_time_key.to_base64(),
        )?;

        let text = "It's a secret to everybody";
        let message = alice_session.encrypt(text).into();

        let identity_key = PublicKey::from_base64(alice.parsed_identity_keys().curve25519())?;

        let InboundCreationResult { session, plaintext } = if let OlmMessage::PreKey(m) = &message {
            bob.create_inbound_session(identity_key, m)?
        } else {
            bail!("Got invalid message type from olm_rs {:?}", message);
        };

        assert_eq!(alice_session.session_id(), session.session_id());
        assert!(bob.one_time_keys.private_keys.is_empty());

        assert_eq!(text.as_bytes(), plaintext);

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

        let alice_session = alice.create_outbound_session(
            &bob.curve25519_key().to_base64(),
            &one_time_key.to_base64(),
        )?;

        let text = "It's a secret to everybody";

        let message = alice_session.encrypt(text).into();
        let identity_key = PublicKey::from_base64(alice.parsed_identity_keys().curve25519())?;

        if let OlmMessage::PreKey(m) = &message {
            let InboundCreationResult { session, plaintext } =
                bob.create_inbound_session(identity_key, m)?;

            assert_eq!(m.session_keys(), session.session_keys());
            assert_eq!(alice_session.session_id(), session.session_id());
            assert!(bob.fallback_keys.fallback_key.is_some());

            assert_eq!(text.as_bytes(), plaintext);
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

        let key = b"DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.to_vec() });

        let unpickled = Account::from_libolm_pickle(&pickle, key)?;

        assert_eq!(olm.parsed_identity_keys().ed25519(), unpickled.ed25519_key().to_base64());
        assert_eq!(olm.parsed_identity_keys().curve25519(), unpickled.curve25519_key().to_base64());

        let mut olm_one_time_keys: Vec<_> =
            olm.parsed_one_time_keys().curve25519().values().map(|k| k.to_owned()).collect();
        let mut one_time_keys: Vec<_> =
            unpickled.one_time_keys().values().map(|k| k.to_base64()).collect();

        // We generated 10 one-time keys on the libolm side, we expect the next key id
        // to be 11.
        assert_eq!(unpickled.one_time_keys.next_key_id, 11);

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
    fn pickle_cycle_with_one_fallback_key() {
        let mut alice = Account::new();
        alice.generate_fallback_key();

        let mut encoded = Vec::<u8>::new();
        let pickle = Pickle::from(&alice);
        let size = pickle.encode(&mut encoded).expect("Should encode pickle");
        assert_eq!(size, encoded.len());

        let account =
            Account::from_decrypted_libolm_pickle(&encoded).expect("Should unpickle account");

        let key_bytes = alice
            .fallback_key()
            .values()
            .next()
            .expect("Should have a fallback key before encoding")
            .to_bytes();
        let decoded_key_bytes = account
            .fallback_key()
            .values()
            .next()
            .expect("Should have a fallback key after decoding")
            .to_bytes();
        assert_eq!(key_bytes, decoded_key_bytes);
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn pickle_cycle_with_two_fallback_keys() {
        let mut alice = Account::new();
        alice.generate_fallback_key();
        alice.generate_fallback_key();

        let mut encoded = Vec::<u8>::new();
        let pickle = Pickle::from(&alice);
        let size = pickle.encode(&mut encoded).expect("Should encode pickle");
        assert_eq!(size, encoded.len());

        let account =
            Account::from_decrypted_libolm_pickle(&encoded).expect("Should unpickle account");

        let key_bytes = alice
            .fallback_key()
            .values()
            .next()
            .expect("Should have a fallback key before encoding")
            .to_bytes();
        let decoded_key_bytes = account
            .fallback_key()
            .values()
            .next()
            .expect("Should have a fallback key after decoding")
            .to_bytes();
        assert_eq!(key_bytes, decoded_key_bytes);
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn signing_with_expanded_key() -> Result<()> {
        let olm = OlmAccount::new();
        olm.generate_one_time_keys(10);
        olm.generate_fallback_key();

        let key = b"DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.to_vec() });

        let account_with_expanded_key = Account::from_libolm_pickle(&pickle, key)?;

        // The clone is needed since we're later on using the account.
        #[allow(clippy::redundant_clone)]
        let signing_key_clone = account_with_expanded_key.signing_key.clone();
        signing_key_clone.sign("You met with a terrible fate, haven’t you?".as_bytes());
        account_with_expanded_key.sign("You met with a terrible fate, haven’t you?".as_bytes());

        Ok(())
    }

    #[test]
    fn invalid_session_creation_does_not_remove_otk() -> Result<()> {
        let mut alice = Account::new();
        let malory = Account::new();
        alice.generate_one_time_keys(1);

        let mut session = malory.create_outbound_session(
            SessionConfig::default(),
            alice.curve25519_key(),
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
                !alice.one_time_keys.private_keys.is_empty(),
                "The one-time key was removed when it shouldn't"
            );

            Ok(())
        } else {
            bail!("Invalid message type");
        }
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn fuzz_corpus_unpickling() {
        crate::run_corpus("olm-account-unpickling", |data| {
            let _ = Account::from_decrypted_libolm_pickle(data);
        });
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn libolm_pickle_cycle() -> Result<()> {
        let message = "It's a secret to everybody";

        let olm = OlmAccount::new();
        olm.generate_one_time_keys(10);
        olm.generate_fallback_key();

        let olm_signature = olm.sign(message);

        let key = b"DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.to_vec() });

        let account = Account::from_libolm_pickle(&pickle, key).unwrap();
        let vodozemac_pickle = account.to_libolm_pickle(key).unwrap();
        let _ = Account::from_libolm_pickle(&vodozemac_pickle, key).unwrap();

        let vodozemac_signature = account.sign(message.as_bytes());
        let olm_signature = crate::types::Ed25519Signature::from_base64(&olm_signature)
            .expect("We should be able to parse a signature produced by libolm");
        account
            .identity_keys()
            .ed25519
            .verify(message.as_bytes(), &olm_signature)
            .expect("We should be able to verify the libolm signature with our vodozemac Account");

        let unpickled = OlmAccount::unpickle(
            vodozemac_pickle,
            olm_rs::PicklingMode::Encrypted { key: key.to_vec() },
        )
        .unwrap();

        let utility = olm_rs::utility::OlmUtility::new();
        utility
            .ed25519_verify(
                unpickled.parsed_identity_keys().ed25519(),
                message,
                vodozemac_signature.to_base64(),
            )
            .expect("We should be able to verify the signature vodozemac created");
        utility
            .ed25519_verify(
                unpickled.parsed_identity_keys().ed25519(),
                message,
                olm_signature.to_base64(),
            )
            .expect("We should be able to verify the original signature from libolm");

        assert_eq!(olm.parsed_identity_keys(), unpickled.parsed_identity_keys());

        Ok(())
    }

    #[test]
    fn decrypt_with_dehydrated_device() {
        let mut alice = Account::new();
        let bob = Account::new();
        let carol = Account::new();

        alice.generate_one_time_keys(alice.max_number_of_one_time_keys());
        alice.generate_fallback_key();

        let alice_dehydrated_result =
            alice.to_dehydrated_device(&PICKLE_KEY).expect("Should be able to dehydrate device");

        // encrypt using a one-time key
        let mut bob_session = bob.create_outbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            *alice
                .one_time_keys()
                .iter()
                .next()
                .expect("Failed getting alice's OTK, which should never happen here.")
                .1,
        );

        // encrypt using a fallback key
        let mut carol_session = carol.create_outbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            *alice
                .fallback_key()
                .iter()
                .next()
                .expect("Failed getting alice's fallback key, which should never happen here.")
                .1,
        );

        let message = "It's a secret to everybody";
        let bob_olm_message = bob_session.encrypt(message);
        let carol_olm_message = carol_session.encrypt(message);

        let mut alice_rehydrated = Account::from_dehydrated_device(
            &alice_dehydrated_result.ciphertext,
            &alice_dehydrated_result.nonce,
            &PICKLE_KEY,
        )
        .expect("Should be able to rehydrate device");

        // make sure we can decrypt both messages
        let prekey_message = assert_matches!(bob_olm_message, OlmMessage::PreKey(m) => m);
        let InboundCreationResult { session: alice_session, plaintext } = alice_rehydrated
            .create_inbound_session(bob.curve25519_key(), &prekey_message)
            .expect("Alice should be able to create an inbound session from Bob's pre-key message");
        assert_eq!(alice_session.session_id(), bob_session.session_id());
        assert_eq!(message.as_bytes(), plaintext);

        let prekey_message = assert_matches!(carol_olm_message, OlmMessage::PreKey(m) => m);
        let InboundCreationResult { session: alice_session, plaintext } = alice_rehydrated
            .create_inbound_session(carol.curve25519_key(), &prekey_message)
            .expect(
                "Alice should be able to create an inbound session from Carol's pre-key message",
            );

        assert_eq!(alice_session.session_id(), carol_session.session_id());
        assert_eq!(message.as_bytes(), plaintext);
    }

    #[test]
    fn fails_to_rehydrate_with_wrong_key() {
        let mut alice = Account::new();

        alice.generate_one_time_keys(alice.max_number_of_one_time_keys());
        alice.generate_fallback_key();

        let alice_dehydrated_result =
            alice.to_dehydrated_device(&PICKLE_KEY).expect("Should be able to dehydrate device");

        assert!(Account::from_dehydrated_device(
            &alice_dehydrated_result.ciphertext,
            &alice_dehydrated_result.nonce,
            &[1; 32],
        )
        .is_err());

        assert!(Account::from_dehydrated_device(
            &alice_dehydrated_result.ciphertext,
            "WrongNonce123456",
            &PICKLE_KEY,
        )
        .is_err());
    }

    #[derive(Encode, Decode)]
    struct OptFallbackPickleTest {
        fallback1: dehydrated_device::OptFallbackKey,
        fallback2: dehydrated_device::OptFallbackKey,
    }

    #[test]
    fn encodes_optional_fallback_key() {
        use std::io::Cursor;

        let data_to_pickle = OptFallbackPickleTest {
            fallback1: dehydrated_device::OptFallbackKey {
                fallback_key: Some(dehydrated_device::OneTimeKey {
                    private_key: Box::new([1; 32]),
                }),
            },
            fallback2: dehydrated_device::OptFallbackKey { fallback_key: None },
        };

        let buffer = Vec::<u8>::new();
        let mut cursor = Cursor::new(buffer);
        let pickle_length = data_to_pickle.encode(&mut cursor).expect("Can pickle data");
        let pickle = cursor.into_inner();
        assert_eq!(pickle.len(), pickle_length);

        let mut cursor = Cursor::new(&pickle);
        let unpickled_data = OptFallbackPickleTest::decode(&mut cursor).expect("Can unpickle");

        assert!(unpickled_data.fallback1.fallback_key.is_some());
        assert!(unpickled_data.fallback2.fallback_key.is_none());
    }

    #[test]
    fn decrypted_dehydration_cycle() {
        use dehydrated_device::Pickle;

        let alice = Account::new();

        let mut encoded = Vec::<u8>::new();
        let pickle = Pickle::from(&alice);
        let size = pickle.encode(&mut encoded).expect("Should dehydrate");
        assert_eq!(size, encoded.len());

        let account =
            Account::from_decrypted_dehydrated_device(&encoded).expect("Should rehydrate account");

        assert_eq!(alice.identity_keys(), account.identity_keys());
    }
}
