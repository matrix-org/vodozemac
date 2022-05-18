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
mod session_keys;

pub use group_session::{GroupSession, GroupSessionPickle};
pub use inbound_group_session::{
    DecryptedMessage, DecryptionError, InboundGroupSession, InboundGroupSessionPickle,
};
pub use message::MegolmMessage;
pub use session_keys::{ExportedSessionKey, SessionKey, SessionKeyDecodeError};

#[cfg(test)]
mod test {
    use anyhow::Result;
    use olm_rs::{
        inbound_group_session::OlmInboundGroupSession,
        outbound_group_session::OlmOutboundGroupSession,
    };

    use super::{GroupSession, InboundGroupSession};
    use crate::megolm::{GroupSessionPickle, InboundGroupSessionPickle, SessionKey};

    const PICKLE_KEY: [u8; 32] = [0u8; 32];

    #[test]
    fn encrypting() -> Result<()> {
        let mut session = GroupSession::new();
        let session_key = session.session_key();

        let olm_session = OlmInboundGroupSession::new(&session_key.to_base64())?;

        let plaintext = "It's a secret to everybody";
        let message = session.encrypt(plaintext).to_base64();

        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        let plaintext = "Another secret";
        let message = session.encrypt(plaintext).to_base64();

        let (decrypted, _) = olm_session.decrypt(message)?;
        assert_eq!(decrypted, plaintext);

        let plaintext = "And another secret";
        let message = session.encrypt(plaintext).to_base64();
        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        let plaintext = "Last secret";

        for _ in 1..2000 {
            session.encrypt(plaintext);
        }

        let message = session.encrypt(plaintext).to_base64();
        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn decrypting() -> Result<()> {
        let olm_session = OlmOutboundGroupSession::new();

        let session_key = SessionKey::from_base64(&olm_session.session_key())?;

        let mut session = InboundGroupSession::new(&session_key);

        let plaintext = "Hello";
        let message = olm_session.encrypt(plaintext).as_str().try_into()?;

        let decrypted = session.decrypt(&message)?;

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.message_index, 0);

        let plaintext = "Another secret";
        let message = olm_session.encrypt(plaintext).as_str().try_into()?;

        let decrypted = session.decrypt(&message)?;

        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.message_index, 1);

        let third_plaintext = "And another secret";
        let third_message = olm_session.encrypt(third_plaintext).as_str().try_into()?;
        let decrypted = session.decrypt(&third_message)?;

        assert_eq!(decrypted.plaintext, third_plaintext);
        assert_eq!(decrypted.message_index, 2);

        let plaintext = "Last secret";

        for _ in 1..2000 {
            olm_session.encrypt(plaintext);
        }

        let message = olm_session.encrypt(plaintext).as_str().try_into()?;
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
        let mut inbound = InboundGroupSession::new(&session.session_key());

        assert_eq!(session.session_id(), inbound.session_id());

        let first_plaintext = "It's a secret to everybody";
        let first_message = session.encrypt(first_plaintext);
        let second_plaintext = "It's dangerous to go alone. Take this!";
        let second_message = session.encrypt(second_plaintext);

        let decrypted = inbound.decrypt(&first_message)?;

        assert_eq!(decrypted.plaintext, first_plaintext);
        assert_eq!(decrypted.message_index, 0);

        let export = inbound.export_at(1).expect("Can export at the initial index.");
        let mut imported = InboundGroupSession::import(&export);

        assert_eq!(session.session_id(), imported.session_id());

        imported.decrypt(&first_message).expect_err("Can't decrypt at the initial index.");
        let second_decrypted =
            imported.decrypt(&second_message).expect("Can decrypt at the next index.");
        assert_eq!(
            second_plaintext, second_decrypted.plaintext,
            "Decrypted plaintext differs from original."
        );
        assert_eq!(1, second_decrypted.message_index, "Expected message index to be 1.");

        assert!(imported.export_at(0).is_none(), "Can't export at the initial index.");
        assert!(imported.export_at(1).is_some(), "Can export at the next index.");

        Ok(())
    }

    #[test]
    fn group_session_pickling_roundtrip_is_identity() -> Result<()> {
        let session = GroupSession::new();

        let pickle = session.pickle().encrypt(&PICKLE_KEY);

        let decrypted_pickle = GroupSessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let unpickled_group_session = GroupSession::from_pickle(decrypted_pickle);
        let repickle = unpickled_group_session.pickle();

        assert_eq!(session.session_id(), unpickled_group_session.session_id());

        let decrypted_pickle = GroupSessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let pickle = serde_json::to_value(decrypted_pickle)?;
        let repickle = serde_json::to_value(repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    fn inbound_group_session_pickling_roundtrip_is_identity() -> Result<()> {
        let session = GroupSession::new();
        let session = InboundGroupSession::from(&session);

        let pickle = session.pickle().encrypt(&PICKLE_KEY);

        let decrypted_pickle = InboundGroupSessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let unpickled_group_session = InboundGroupSession::from_pickle(decrypted_pickle);
        let repickle = unpickled_group_session.pickle();

        assert_eq!(session.session_id(), unpickled_group_session.session_id());

        let decrypted_pickle = InboundGroupSessionPickle::from_encrypted(&pickle, &PICKLE_KEY)?;
        let pickle = serde_json::to_value(decrypted_pickle)?;
        let repickle = serde_json::to_value(repickle)?;

        assert_eq!(pickle, repickle);

        Ok(())
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn libolm_unpickling() -> Result<()> {
        let session = GroupSession::new();
        let session_key = session.session_key();

        let olm = OlmInboundGroupSession::new(&session_key.to_base64())?;

        let key = "DEFAULT_PICKLE_KEY";
        let pickle = olm.pickle(olm_rs::PicklingMode::Encrypted { key: key.as_bytes().to_vec() });

        let unpickled = InboundGroupSession::from_libolm_pickle(&pickle, key)?;

        assert_eq!(olm.session_id(), unpickled.session_id());
        assert_eq!(olm.first_known_index(), unpickled.first_known_index());

        Ok(())
    }
}
