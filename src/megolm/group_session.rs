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

use serde::{Deserialize, Serialize};

use super::{
    default_config, message::MegolmMessage, ratchet::Ratchet, session_config::Version,
    session_keys::SessionKey, SessionConfig,
};
use crate::{
    cipher::Cipher,
    types::Ed25519Keypair,
    utilities::{pickle, unpickle},
    PickleError,
};

/// A Megolm group session represents a single sending participant in an
/// encrypted group communication context containing multiple receiving parties.
///
/// A group session consists of a ratchet, used for encryption, and an Ed25519
/// signing key pair, used for authenticity.
///
/// A group session containing the signing key pair is also known as an
/// "outbound" group session. We differentiate this from an *inbound* group
/// session where this key pair has been removed and which can be used solely
/// for receipt and decryption of messages.
///
/// Such an inbound group session is typically sent by the outbound group
/// session owner to each of the receiving parties via a secure peer-to-peer
/// channel (e.g. an Olm channel).
pub struct GroupSession {
    ratchet: Ratchet,
    signing_key: Ed25519Keypair,
    config: SessionConfig,
}

impl Default for GroupSession {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl GroupSession {
    /// Construct a new group session, with a random ratchet state and signing
    /// key pair.
    pub fn new(config: SessionConfig) -> Self {
        let signing_key = Ed25519Keypair::new();
        Self { signing_key, ratchet: Ratchet::new(), config }
    }

    /// Returns the globally unique session ID, in base64-encoded form.
    ///
    /// A session ID is the public part of the Ed25519 key pair associated with
    /// the group session. Due to the construction, every session ID is
    /// (probabilistically) globally unique.
    pub fn session_id(&self) -> String {
        self.signing_key.public_key().to_base64()
    }

    /// Return the current message index.
    ///
    /// The message index is incremented each time a message is encrypted with
    /// the group session.
    pub fn message_index(&self) -> u32 {
        self.ratchet.index()
    }

    pub fn session_config(&self) -> SessionConfig {
        self.config
    }

    /// Encrypt the `plaintext` with the group session.
    ///
    /// The resulting ciphertext is MAC-ed, then signed with the group session's
    /// Ed25519 key pair and finally base64-encoded.
    pub fn encrypt(&mut self, plaintext: impl AsRef<[u8]>) -> MegolmMessage {
        let cipher = Cipher::new_megolm(self.ratchet.as_bytes());

        let message = match self.config.version {
            Version::V1 => MegolmMessage::encrypt_truncated_mac(
                self.message_index(),
                &cipher,
                &self.signing_key,
                plaintext.as_ref(),
            ),
            Version::V2 => MegolmMessage::encrypt_private(
                self.message_index(),
                &cipher,
                &self.signing_key,
                plaintext.as_ref(),
            ),
        };

        self.ratchet.advance();

        message
    }

    /// Export the group session into a session key.
    ///
    /// The session key contains the key version constant, the current message
    /// index, the ratchet state and the *public* part of the signing key pair.
    /// It is signed by the signing key pair for authenticity.
    ///
    /// The session key is in a portable format, suitable for sending over the
    /// network. It is typically sent to other group participants so that they
    /// can reconstruct an inbound group session in order to decrypt messages
    /// sent by this group session.
    pub fn session_key(&self) -> SessionKey {
        let mut session_key = SessionKey::new(&self.ratchet, self.signing_key.public_key());
        let signature = self.signing_key.sign(&session_key.to_signature_bytes());
        session_key.signature = signature;

        session_key
    }

    /// Convert the group session into a struct which implements
    /// [`serde::Serialize`] and [`serde::Deserialize`].
    pub fn pickle(&self) -> GroupSessionPickle {
        GroupSessionPickle {
            ratchet: self.ratchet.clone(),
            signing_key: self.signing_key.clone(),
            config: self.config,
        }
    }

    /// Restore a [`GroupSession`] from a previously saved
    /// [`GroupSessionPickle`].
    pub fn from_pickle(pickle: GroupSessionPickle) -> Self {
        pickle.into()
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &[u8],
    ) -> Result<Self, crate::LibolmPickleError> {
        use std::io::Read;

        use zeroize::Zeroize;

        use crate::{
            megolm::libolm::LibolmRatchetPickle,
            utilities::{unpickle_libolm, Decode, LibolmEd25519Keypair},
        };

        #[derive(Zeroize)]
        #[zeroize(drop)]
        struct Pickle {
            version: u32,
            ratchet: LibolmRatchetPickle,
            ed25519_keypair: LibolmEd25519Keypair,
        }

        impl Decode for Pickle {
            fn decode(reader: &mut impl Read) -> Result<Self, crate::utilities::LibolmDecodeError> {
                Ok(Pickle {
                    version: u32::decode(reader)?,
                    ratchet: LibolmRatchetPickle::decode(reader)?,
                    ed25519_keypair: LibolmEd25519Keypair::decode(reader)?,
                })
            }
        }

        impl TryFrom<Pickle> for GroupSession {
            type Error = crate::LibolmPickleError;

            fn try_from(pickle: Pickle) -> Result<Self, Self::Error> {
                // Removing the borrow doesn't work and clippy complains about
                // this on nightly.
                #[allow(clippy::needless_borrow)]
                let ratchet = (&pickle.ratchet).into();
                let signing_key =
                    Ed25519Keypair::from_expanded_key(&pickle.ed25519_keypair.private_key)?;

                Ok(Self { ratchet, signing_key, config: SessionConfig::version_1() })
            }
        }

        const PICKLE_VERSION: u32 = 1;

        unpickle_libolm::<Pickle, _>(pickle, pickle_key, PICKLE_VERSION)
    }
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`GroupSession::pickle`].
#[derive(Serialize, Deserialize)]
pub struct GroupSessionPickle {
    ratchet: Ratchet,
    signing_key: Ed25519Keypair,
    #[serde(default = "default_config")]
    config: SessionConfig,
}

impl GroupSessionPickle {
    /// Serialize and encrypt the pickle using the given key.
    ///
    /// This is the inverse of [`GroupSessionPickle::from_encrypted`].
    pub fn encrypt(self, pickle_key: &[u8; 32]) -> String {
        pickle(&self, pickle_key)
    }

    /// Obtain a pickle from a ciphertext by decrypting and deserializing using
    /// the given key.
    ///
    /// This is the inverse of [`GroupSessionPickle::encrypt`].
    pub fn from_encrypted(ciphertext: &str, pickle_key: &[u8; 32]) -> Result<Self, PickleError> {
        unpickle(ciphertext, pickle_key)
    }
}

impl From<GroupSessionPickle> for GroupSession {
    fn from(pickle: GroupSessionPickle) -> Self {
        Self { ratchet: pickle.ratchet, signing_key: pickle.signing_key, config: pickle.config }
    }
}
