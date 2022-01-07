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

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    message::EncodedMegolmMessage,
    ratchet::{MegolmRatchetUnpicklingError, Ratchet, RatchetPickle},
    SessionKey, SESSION_KEY_VERSION,
};
use crate::{cipher::Cipher, types::Ed25519Keypair, utilities::base64_encode};

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
#[derive(Deserialize)]
#[serde(try_from = "GroupSessionPickle")]
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
    pub fn encrypt(&mut self, plaintext: &str) -> String {
        let cipher = Cipher::new_megolm(self.ratchet.as_bytes());

        let ciphertext = cipher.encrypt(plaintext.as_ref());
        let mut message = EncodedMegolmMessage::new(ciphertext, self.message_index());

        let mac = cipher.mac(message.bytes_for_mac());
        message.append_mac(mac);

        let signature = self.signing_key.sign(message.bytes_for_signing());
        message.append_signature(signature);

        self.ratchet.advance();

        base64_encode(message)
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
        GroupSessionPickle {
            ratchet: self.ratchet.clone().into(),
            signing_key: self.signing_key.clone(),
        }
    }

    /// Pickle the group session and serialize it to a JSON string.
    ///
    /// The string is wrapped in [`GroupSessionPickledJSON`] which can be
    /// derefed to access the content as a string slice. The string will zeroize
    /// itself when it drops to prevent secrets contained inside from lingering
    /// in memory.
    ///
    /// [`GroupSessionPickledJSON`]: self::GroupSessionPickledJSON
    pub fn pickle_to_json_string(&self) -> GroupSessionPickledJSON {
        let pickle: GroupSessionPickle = self.pickle();
        GroupSessionPickledJSON(
            serde_json::to_string_pretty(&pickle).expect("Group session serialization failed."),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct GroupSessionPickle {
    ratchet: RatchetPickle,
    signing_key: Ed25519Keypair,
}

/// A format suitable for serialization which implements [`serde::Serialize`]
/// and [`serde::Deserialize`]. Obtainable by calling [`GroupSession::pickle`].
impl GroupSessionPickle {
    /// Convert the pickle format back into a [`GroupSession`].
    pub fn unpickle(self) -> Result<GroupSession, GroupSessionUnpicklingError> {
        self.try_into()
    }
}

impl TryFrom<GroupSessionPickle> for GroupSession {
    type Error = GroupSessionUnpicklingError;

    fn try_from(pickle: GroupSessionPickle) -> Result<Self, Self::Error> {
        Ok(Self { ratchet: pickle.ratchet.try_into()?, signing_key: pickle.signing_key })
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct GroupSessionPickledJSON(String);

impl GroupSessionPickledJSON {
    /// Access the serialized content as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Try to convert the serialized JSON string back into a [`GroupSession`].
    pub fn unpickle(self) -> Result<GroupSession, GroupSessionUnpicklingError> {
        let pickle: GroupSessionPickle = serde_json::from_str(&self.0)?;
        pickle.unpickle()
    }
}

impl AsRef<str> for GroupSessionPickledJSON {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for GroupSessionPickledJSON {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[derive(Error, Debug)]
pub enum GroupSessionUnpicklingError {
    #[error("Invalid ratchet")]
    InvalidRatchet(#[from] MegolmRatchetUnpicklingError),
    #[error("Pickle format corrupted: {0}")]
    CorruptedPickle(#[from] serde_json::error::Error),
}
