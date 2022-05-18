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

//! An implementation of the Megolm ratchet.

mod group_session;
mod inbound_group_session;
pub(crate) mod message;
mod ratchet;

pub use group_session::{GroupSession, GroupSessionPickledJSON};
pub use inbound_group_session::{
    DecryptionError, ExportedSessionKey, InboundGroupSession, SessionCreationError,
};
use zeroize::Zeroize;

#[derive(Zeroize)]
pub struct SessionKey(pub String);

impl SessionKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

const SESSION_KEY_VERSION: u8 = 2;

#[cfg(test)]
mod test {
    use anyhow::Result;
    use olm_rs::{
        inbound_group_session::OlmInboundGroupSession,
        outbound_group_session::OlmOutboundGroupSession, PicklingMode,
    };

    use super::{GroupSession, InboundGroupSession, SessionKey};

    #[test]
    fn encrypting() -> Result<()> {
        let mut session = GroupSession::new();
        let session_key = session.session_key();

        let olm_session = OlmInboundGroupSession::new(session_key.as_str())?;

        let plaintext = "It's a secret to everybody";
        let message = session.encrypt(plaintext);

        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        let plaintext = "Another secret";
        let message = session.encrypt(plaintext);

        let (decrypted, _) = olm_session.decrypt(message)?;
        assert_eq!(decrypted, plaintext);

        let plaintext = "And another secret";
        let message = session.encrypt(plaintext);
        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        let plaintext = "Last secret";

        for _ in 1..2000 {
            session.encrypt(plaintext);
        }

        let message = session.encrypt(plaintext);
        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn decrypting() -> Result<()> {
        let olm_session = OlmOutboundGroupSession::new();

        let session_key = SessionKey(olm_session.session_key());

        let mut session = InboundGroupSession::new(&session_key)?;

        let plaintext = "It's a secret to everybody";
        let message = olm_session.encrypt(plaintext);

        let decrypted = session.decrypt(&message)?;

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.message_index, 0);

        let plaintext = "Another secret";
        let message = olm_session.encrypt(plaintext);

        let decrypted = session.decrypt(&message)?;

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.message_index, 1);

        let third_plaintext = "And another secret";
        let third_message = olm_session.encrypt(third_plaintext);
        let decrypted = session.decrypt(&third_message)?;

        assert_eq!(decrypted.plaintext, third_plaintext);
        assert_eq!(decrypted.message_index, 2);

        let plaintext = "Last secret";

        for _ in 1..2000 {
            olm_session.encrypt(plaintext);
        }

        let message = olm_session.encrypt(plaintext);
        let decrypted = session.decrypt(&message)?;

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.message_index, 2002);

        let decrypted = session.decrypt(&third_message)?;

        assert_eq!(decrypted.plaintext, third_plaintext);
        assert_eq!(decrypted.message_index, 2);

        Ok(())
    }

    #[test]
    fn exporting() -> Result<()> {
        let mut session = GroupSession::new();
        let mut inbound = InboundGroupSession::new(&session.session_key())?;

        assert_eq!(session.session_id(), inbound.session_id());

        let plaintext = "It's a secret to everybody";
        let message = session.encrypt(plaintext);

        let decrypted = inbound.decrypt(&message)?;

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.message_index, 0);

        let export = inbound.export_at(1).expect("Can export at the initial index");
        let mut imported = InboundGroupSession::import(&export)?;

        assert_eq!(session.session_id(), imported.session_id());
        imported.decrypt(&message).expect_err("Can't decrypt at the initial index");
        assert!(imported.export_at(0).is_none(), "Can't export at the initial index");

        Ok(())
    }

    #[test]
    fn group_session_pickling_roundtrip_is_identity() -> Result<()> {
        let session = GroupSession::new();

        let pickle = session.pickle_to_json_string();

        let unpickled_group_session: GroupSession = serde_json::from_str(&pickle)?;
        let repickle = unpickled_group_session.pickle_to_json_string();

        let pickle: serde_json::Value = serde_json::from_str(&pickle)?;
        let repickle: serde_json::Value = serde_json::from_str(&repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    fn inbound_group_session_pickling_roundtrip_is_identity() -> Result<()> {
        let session = GroupSession::new();
        let inbound = InboundGroupSession::new(&session.session_key())?;

        let pickle = inbound.pickle_to_json_string();

        let unpickled_inbound: InboundGroupSession = serde_json::from_str(&pickle)?;
        let repickle = unpickled_inbound.pickle_to_json_string();

        let pickle: serde_json::Value = serde_json::from_str(&pickle)?;
        let repickle: serde_json::Value = serde_json::from_str(&repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    fn libolm_unpickling() -> Result<()> {
        let session = GroupSession::new();
        let session_key = session.session_key();

        let olm = OlmInboundGroupSession::new(session_key.as_str())?;

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

        let unpickled = InboundGroupSession::from_libolm_pickle(&pickle, key)?;

        assert_eq!(olm.session_id(), unpickled.session_id());
        assert_eq!(olm.first_known_index(), unpickled.first_known_index());

        Ok(())
    }
}
