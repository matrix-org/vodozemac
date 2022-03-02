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
use zeroize::Zeroize;

use super::{message::MegolmMessage, ratchet::Ratchet, SessionKey, SESSION_KEY_VERSION};
use crate::{
    cipher::Cipher,
    types::Ed25519Keypair,
    utilities::{base64_encode, pickle, unpickle},
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
}

impl Default for GroupSession {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupSession {
    /// Construct a new group session, with a random ratchet state and signing
    /// key pair.
    pub fn new() -> Self {
        let signing_key = Ed25519Keypair::new();
        Self { signing_key, ratchet: Ratchet::new() }
    }

    /// Returns the globally unique session ID, in base64-encoded form.
    ///
    /// A session ID is the public part of the Ed25519 key pair associated with
    /// the group session. Due to the construction, every session ID is
    /// (probabilistically) globally unique.
    pub fn session_id(&self) -> &str {
        self.signing_key.public_key_encoded()
    }

    /// Return the current message index.
    ///
    /// The message index is incremented each time a message is encrypted with
    /// the group session.
    pub fn message_index(&self) -> u32 {
        self.ratchet.index()
    }

    /// Encrypt the `plaintext` with the group session.
    ///
    /// The resulting ciphertext is MAC-ed, then signed with the group session's
    /// Ed25519 key pair and finally base64-encoded.
    pub fn encrypt(&mut self, plaintext: &str) -> MegolmMessage {
        let cipher = Cipher::new_megolm(self.ratchet.as_bytes());

        let ciphertext = cipher.encrypt(plaintext.as_ref());
        let mut message = MegolmMessage::new(ciphertext, self.message_index());

        let mac = cipher.mac(&message.to_mac_bytes());
        message.mac = mac.truncate();

        let signature = self.signing_key.sign(&message.to_signature_bytes());
        message.signature = signature;

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
        let index = self.ratchet.index().to_be_bytes();

        let mut export: Vec<u8> = [
            [SESSION_KEY_VERSION].as_ref(),
            index.as_ref(),
            self.ratchet.as_bytes(),
            self.signing_key.public_key().as_bytes(),
        ]
        .concat();

        let signature = self.signing_key.sign(&export);
        export.extend(signature.to_bytes());

        let result = base64_encode(&export);
        export.zeroize();

        SessionKey(result)
    }

    /// Convert the group session into a struct which implements
    /// [`serde::Serialize`] and [`serde::Deserialize`].
    pub fn pickle(&self) -> GroupSessionPickle {
        GroupSessionPickle { ratchet: self.ratchet.clone(), signing_key: self.signing_key.clone() }
    }

    /// Restore a [`GroupSession`] from a previously saved
    /// [`GroupSessionPickle`].
    pub fn from_pickle(pickle: GroupSessionPickle) -> Self {
        pickle.into()
    }
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`GroupSession::pickle`].
#[derive(Serialize, Deserialize)]
pub struct GroupSessionPickle {
    ratchet: Ratchet,
    signing_key: Ed25519Keypair,
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
        Self { ratchet: pickle.ratchet, signing_key: pickle.signing_key }
    }
}
