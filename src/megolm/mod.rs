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

#![allow(dead_code)]

mod group_session;
mod inbound_group_session;
mod message;
mod ratchet;

pub use group_session::GroupSession;
pub use inbound_group_session::InboundGroupSession;

const SESSION_KEY_VERSION: u8 = 2;

#[cfg(test)]
mod test {
    use anyhow::Result;
    use olm_rs::{
        inbound_group_session::OlmInboundGroupSession,
        outbound_group_session::OlmOutboundGroupSession,
    };

    use super::{GroupSession, InboundGroupSession};

    #[test]
    fn encrypting() -> Result<()> {
        let mut session = GroupSession::new();
        let session_key = session.session_key();

        let olm_session = OlmInboundGroupSession::new(&session_key)?;

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

        let mut session = InboundGroupSession::new(olm_session.session_key())?;

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
}
