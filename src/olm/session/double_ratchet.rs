// Copyright 2021 Damir Jelić
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

use std::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};

use super::{
    chain_key::ChainKey,
    message_key::MessageKey,
    ratchet::{Ratchet, RatchetPublicKey, RemoteRatchetKey},
    receiver_chain::ReceiverChain,
    root_key::{RemoteRootKey, RootKey},
};
use crate::olm::session::ratchet::RatchetKey;
use crate::olm::{messages::Message, shared_secret::Shared3DHSecret};

/// The sender side of a double-ratchet implementation.
///
/// While we are encrypting messages, we are in the "active" state. Here we need
/// to keep track of the latest chain key `C`<sub>`i`,`j`</sub> (so that we can
/// advance to the next one), and also the current root key `R`<sub>`i`</sub>
/// and our most recent ratchet key `T`<sub>`i`</sub> (so that we can calculate
/// the *next* root key).
///
/// Once we receive a message, we transition to the "inactive" state. Since we
/// don't handle decryption here (that's done in [`ReceiverChain`]), we don't
/// need to keep track of the sender's chain key. All we need is enough state so
/// that we can calculate the next root key once we start encrypting again:
/// specifically, the public part of the other side's ratchet key
/// `T`<sub>`i`</sub> which was sent to us in the message, and the remote root
/// key `R`<sub>`i`</sub>.
#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub(super) struct DoubleRatchet {
    inner: DoubleRatchetState,
}

impl DoubleRatchet {
    pub fn next_message_key(&mut self) -> MessageKey {
        match &mut self.inner {
            DoubleRatchetState::Inactive(ratchet) => {
                let mut ratchet = ratchet.activate();

                let message_key = ratchet.next_message_key();
                self.inner = DoubleRatchetState::Active(ratchet);

                message_key
            }
            DoubleRatchetState::Active(ratchet) => ratchet.next_message_key(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Message {
        self.next_message_key().encrypt(plaintext)
    }

    pub fn encrypt_truncated_mac(&mut self, plaintext: &[u8]) -> Message {
        self.next_message_key().encrypt_truncated_mac(plaintext)
    }

    /// Create a new `DoubleRatchet` instance, based on a newly-calculated
    /// shared secret.
    pub fn active(shared_secret: Shared3DHSecret) -> Self {
        let (root_key, chain_key) = shared_secret.expand();

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        let ratchet = ActiveDoubleRatchet {
            parent_ratchet_key: None, // First chain in a session lacks parent ratchet key
            ratchet_count: RatchetCount::new(),
            active_ratchet: Ratchet::new(root_key),
            symmetric_key_ratchet: chain_key,
        };

        Self { inner: ratchet.into() }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn from_ratchet_and_chain_key(ratchet: Ratchet, chain_key: ChainKey) -> Self {
        Self {
            inner: ActiveDoubleRatchet {
                parent_ratchet_key: None, // libolm pickle did not record parent ratchet key
                ratchet_count: RatchetCount::unknown(), // nor the ratchet count
                active_ratchet: ratchet,
                symmetric_key_ratchet: chain_key,
            }
            .into(),
        }
    }

    pub fn inactive_from_prekey_data(
        root_key: RemoteRootKey,
        ratchet_key: RemoteRatchetKey,
    ) -> Self {
        let ratchet_count = RatchetCount::new();
        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key, ratchet_count };

        Self { inner: ratchet.into() }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn inactive_from_libolm_pickle(
        root_key: RemoteRootKey,
        ratchet_key: RemoteRatchetKey,
    ) -> Self {
        let ratchet_count = RatchetCount::unknown();
        let ratchet = InactiveDoubleRatchet { root_key, ratchet_key, ratchet_count };

        Self { inner: ratchet.into() }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn root_key_bytes(&self) -> Box<[u8; 32]> {
        match &self.inner {
            DoubleRatchetState::Inactive(ratchet) => ratchet.root_key.key.clone(),
            DoubleRatchetState::Active(ratchet) => ratchet.active_ratchet.root_key().key.clone(),
        }
    }

    #[cfg(feature = "libolm-compat")]
    pub fn to_ratchet_and_chain_key(&self) -> Option<(&RatchetKey, &ChainKey)> {
        match &self.inner {
            DoubleRatchetState::Inactive(_) => None,
            DoubleRatchetState::Active(ratchet) => {
                Some((ratchet.active_ratchet.ratchet_key(), &ratchet.symmetric_key_ratchet))
            }
        }
    }

    pub fn advance(&mut self, ratchet_key: RemoteRatchetKey) -> (DoubleRatchet, ReceiverChain) {
        let (ratchet, receiver_chain) = match &self.inner {
            DoubleRatchetState::Active(r) => r.advance(ratchet_key),
            DoubleRatchetState::Inactive(r) => {
                let ratchet = r.activate();
                // Advancing an inactive ratchet shouldn't be possible since the
                // other side did not yet receive our new ratchet key.
                //
                // This will likely end up in a decryption error but for
                // consistency sake and avoiding the leakage of our internal
                // state it's better to error out there.
                let ret = ratchet.advance(ratchet_key);

                self.inner = ratchet.into();

                ret
            }
        };

        (Self { inner: DoubleRatchetState::Inactive(ratchet) }, receiver_chain)
    }
}

impl Debug for DoubleRatchet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_tuple("DoubleRatchet");
        match &self.inner {
            DoubleRatchetState::Inactive(r) => dbg.field(r),
            DoubleRatchetState::Active(r) => dbg.field(r),
        };
        dbg.finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
enum DoubleRatchetState {
    Inactive(InactiveDoubleRatchet),
    Active(ActiveDoubleRatchet),
}

impl From<InactiveDoubleRatchet> for DoubleRatchetState {
    fn from(r: InactiveDoubleRatchet) -> Self {
        Self::Inactive(r)
    }
}

impl From<ActiveDoubleRatchet> for DoubleRatchetState {
    fn from(r: ActiveDoubleRatchet) -> Self {
        Self::Active(r)
    }
}

/// State of the sender-side ratchet when we have received a new chain from the
/// other side, and have not yet created a new chain of our own.
///
/// See [`DoubleRatchet`] for more explanation.
#[derive(Serialize, Deserialize, Clone)]
struct InactiveDoubleRatchet {
    root_key: RemoteRootKey,
    ratchet_key: RemoteRatchetKey,

    /// The number of times the ratchet has been advanced.
    ///
    /// If `root_key` contains root key `R`<sub>`i`</sub>, this is `i`.
    ///
    /// This is not required to implement the algorithm: it is maintained solely
    /// for diagnostic output.
    #[serde(default = "RatchetCount::unknown")]
    ratchet_count: RatchetCount,
}

impl InactiveDoubleRatchet {
    fn activate(&self) -> ActiveDoubleRatchet {
        let (root_key, chain_key, ratchet_key) = self.root_key.advance(&self.ratchet_key);
        let active_ratchet = Ratchet::new_with_ratchet_key(root_key, ratchet_key);

        ActiveDoubleRatchet {
            parent_ratchet_key: Some(self.ratchet_key),
            ratchet_count: self.ratchet_count.advance(),
            active_ratchet,
            symmetric_key_ratchet: chain_key,
        }
    }
}

impl Debug for InactiveDoubleRatchet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InactiveDoubleRatchet")
            .field("ratchet_count", &self.ratchet_count)
            .field("ratchet_key", &self.ratchet_key)
            .finish_non_exhaustive()
    }
}

/// State of the sender-side ratchet while we are in "encryption" mode: we are
/// encrypting our own messages and have not yet received any messages which
/// were created since we started this chain.
///
/// See [`DoubleRatchet`] for more explanation.
#[derive(Serialize, Deserialize, Clone)]
struct ActiveDoubleRatchet {
    /// The other side's most recent ratchet key, which was used to calculate
    /// the root key in `active_ratchet` and the chain key in
    /// `symmetric_key_ratchet`.
    ///
    /// If `active_ratchet` contains root key `R`<sub>`i`</sub> and our own
    /// ratchet key `T`<sub>`i`</sub>, this is `T`<sub>`i-1`</sub>.
    ///
    /// `None` means "unknown", either because this session has been restored
    /// from a pickle which did not record the parent session key, or because
    /// this is the first chain in the session.
    ///
    /// This is not required to implement the algorithm: it is maintained solely
    /// for diagnostic output.
    #[serde(default)]
    parent_ratchet_key: Option<RemoteRatchetKey>,

    /// The number of times the ratchet has been advanced.
    ///
    /// If `active_ratchet` contains root key `R`<sub>`i`</sub>, this is `i`.
    #[serde(default = "RatchetCount::unknown")]
    ratchet_count: RatchetCount,

    active_ratchet: Ratchet,
    symmetric_key_ratchet: ChainKey,
}

impl ActiveDoubleRatchet {
    fn advance(&self, ratchet_key: RemoteRatchetKey) -> (InactiveDoubleRatchet, ReceiverChain) {
        let (root_key, remote_chain) = self.active_ratchet.advance(ratchet_key);

        let new_ratchet_count = self.ratchet_count.advance();
        let ratchet = InactiveDoubleRatchet {
            root_key,
            ratchet_key,
            ratchet_count: new_ratchet_count.clone(),
        };
        let receiver_chain = ReceiverChain::new(ratchet_key, remote_chain, new_ratchet_count);

        (ratchet, receiver_chain)
    }

    fn ratchet_key(&self) -> RatchetPublicKey {
        RatchetPublicKey::from(self.active_ratchet.ratchet_key())
    }

    fn next_message_key(&mut self) -> MessageKey {
        self.symmetric_key_ratchet.create_message_key(self.ratchet_key())
    }
}

impl Debug for ActiveDoubleRatchet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let active_ratchet_public_key: RatchetPublicKey = self.active_ratchet.ratchet_key().into();
        f.debug_struct("ActiveDoubleRatchet")
            .field("ratchet_count", &self.ratchet_count)
            .field("parent_ratchet_key", &self.parent_ratchet_key)
            .field("ratchet_key", &active_ratchet_public_key)
            .field("chain_index", &self.symmetric_key_ratchet.index())
            .finish_non_exhaustive()
    }
}

/// The number of times the ratchet has been advanced, `i`.
///
/// This starts at 0 for the first prekey messages from Alice to Bob,
/// increments to 1 when Bob replies, and then increments each time the
/// conversation changes direction.
///
/// It may be unknown, if the ratchet was restored from a pickle
/// which didn't track it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RatchetCount {
    Known(u64),
    Unknown(()),
}

impl RatchetCount {
    pub const fn new() -> RatchetCount {
        RatchetCount::Known(0)
    }

    pub const fn unknown() -> RatchetCount {
        RatchetCount::Unknown(())
    }

    pub fn advance(&self) -> RatchetCount {
        match self {
            RatchetCount::Known(count) => RatchetCount::Known(count + 1),
            RatchetCount::Unknown(_) => RatchetCount::Unknown(()),
        }
    }
}

impl Debug for RatchetCount {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetCount::Known(count) => write!(f, "{count}"),
            RatchetCount::Unknown(_) => write!(f, "<unknown>"),
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches2::assert_matches;

    use super::{
        ActiveDoubleRatchet, DoubleRatchet, DoubleRatchetState, InactiveDoubleRatchet, RatchetCount,
    };
    use crate::olm::{Account, OlmMessage, Session, SessionConfig};

    fn create_session_pair(alice: &Account, bob: &mut Account) -> (Session, Session) {
        let bob_otks = bob.generate_one_time_keys(1);
        let bob_otk = bob_otks.created.first().expect("Couldn't get a one-time-key for bob");
        let bob_identity_key = bob.identity_keys().curve25519;
        let mut alice_session =
            alice.create_outbound_session(SessionConfig::version_1(), bob_identity_key, *bob_otk);

        let message = "It's a secret to everybody";
        let olm_message = alice_session.encrypt(message);
        assert_matches!(olm_message, OlmMessage::PreKey(prekey_message));

        let alice_identity_key = alice.identity_keys().curve25519;
        let bob_session_creation_result = bob
            .create_inbound_session(alice_identity_key, &prekey_message)
            .expect("Unable to create inbound session");
        assert_eq!(bob_session_creation_result.plaintext, message.as_bytes());
        (alice_session, bob_session_creation_result.session)
    }

    fn assert_active_ratchet(sending_ratchet: &DoubleRatchet) -> &ActiveDoubleRatchet {
        match &sending_ratchet.inner {
            DoubleRatchetState::Inactive(_) => panic!("Not an active ratchet"),
            DoubleRatchetState::Active(s) => s,
        }
    }

    fn assert_inactive_ratchet(sending_ratchet: &DoubleRatchet) -> &InactiveDoubleRatchet {
        match &sending_ratchet.inner {
            DoubleRatchetState::Active(_) => panic!("Not an inactive ratchet"),
            DoubleRatchetState::Inactive(s) => s,
        }
    }

    #[test]
    fn ratchet_counts() {
        let (mut alice_session, mut bob_session) =
            create_session_pair(&Account::new(), &mut Account::new());

        // Both ratchets should start with count 0.
        assert_eq!(
            assert_active_ratchet(&alice_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(0)
        );
        assert_eq!(
            assert_inactive_ratchet(&bob_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(0)
        );

        // Once Bob replies, the ratchets should bump to 1.
        let olm_message = bob_session.encrypt("sssh");
        alice_session.decrypt(&olm_message).expect("Alice could not decrypt message from Bob");
        assert_eq!(
            assert_inactive_ratchet(&alice_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(1)
        );
        assert_eq!(
            assert_active_ratchet(&bob_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(1)
        );

        // Now Alice replies again.
        let olm_message = alice_session.encrypt("sssh");
        bob_session.decrypt(&olm_message).expect("Bob could not decrypt message from Alice");
        assert_eq!(
            assert_active_ratchet(&alice_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(2)
        );
        assert_eq!(
            assert_inactive_ratchet(&bob_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(2)
        );
    }

    #[test]
    #[cfg(feature = "libolm-compat")]
    fn ratchet_counts_for_imported_session() {
        let (_, _, mut alice_session, bob_libolm_session) =
            crate::olm::session::test::session_and_libolm_pair()
                .expect("unable to create sessions");

        // Import the libolm session into a proper Vodozmac session.
        let key = b"DEFAULT_PICKLE_KEY";
        let pickle =
            bob_libolm_session.pickle(olm_rs::PicklingMode::Encrypted { key: key.to_vec() });
        let mut bob_session =
            Session::from_libolm_pickle(&pickle, key).expect("Should be able to unpickle session");

        assert_eq!(
            assert_inactive_ratchet(&bob_session.sending_ratchet).ratchet_count,
            RatchetCount::Unknown(())
        );

        // Once Bob replies, Alice's count bumps to 1, but Bob's remains unknown.
        let olm_message = bob_session.encrypt("sssh");
        alice_session.decrypt(&olm_message).expect("Alice could not decrypt message from Bob");
        assert_eq!(
            assert_inactive_ratchet(&alice_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(1)
        );
        assert_eq!(
            assert_active_ratchet(&bob_session.sending_ratchet).ratchet_count,
            RatchetCount::Unknown(())
        );

        // Now Alice replies again.
        let olm_message = alice_session.encrypt("sssh");
        bob_session.decrypt(&olm_message).expect("Bob could not decrypt message from Alice");
        assert_eq!(
            assert_active_ratchet(&alice_session.sending_ratchet).ratchet_count,
            RatchetCount::Known(2)
        );
        assert_eq!(
            assert_inactive_ratchet(&bob_session.sending_ratchet).ratchet_count,
            RatchetCount::Unknown(())
        );
    }
}
