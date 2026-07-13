// Copyright 2026 The Matrix.org Foundation C.I.C.
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

//! Tests for the additive `*_with_rng` entropy-injection API.
//!
//! These verify that:
//!   * supplying a deterministic RNG to every keygen `_with_rng` variant yields
//!     reproducible keys, sessions, and ciphertext (same RNG state in => same
//!     bytes out);
//!   * distinct RNG states yield distinct keys (the RNG genuinely drives the
//!     keygen);
//!   * a `_with_rng`-built session interoperates with a default (`OsRng`-built)
//!     counterpart, i.e. the seam is behaviour-preserving;
//!   * the lazy Diffie-Hellman ratchet advance inside `encrypt` consumes RNG
//!     bytes exactly when the ratchet turns, so a genuinely-new ratchet step is
//!     reproducible under the same RNG but produces a fresh ephemeral under a
//!     different one.

use rand::{SeedableRng, rngs::StdRng};
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

/// A deterministic, seedable CSPRNG for reproducible test vectors.
fn seeded(seed: u8) -> StdRng {
    StdRng::from_seed([seed; 32])
}

#[test]
fn account_new_with_rng_is_deterministic() {
    let a = Account::new_with_rng(&mut seeded(1));
    let b = Account::new_with_rng(&mut seeded(1));

    assert_eq!(a.curve25519_key(), b.curve25519_key());
    assert_eq!(a.ed25519_key(), b.ed25519_key());
}

#[test]
fn account_new_with_rng_differs_for_distinct_seeds() {
    let a = Account::new_with_rng(&mut seeded(1));
    let b = Account::new_with_rng(&mut seeded(2));

    assert_ne!(a.curve25519_key(), b.curve25519_key());
    assert_ne!(a.ed25519_key(), b.ed25519_key());
}

#[test]
fn generate_one_time_keys_with_rng_is_deterministic() {
    let mut a = Account::new_with_rng(&mut seeded(3));
    let mut b = Account::new_with_rng(&mut seeded(3));

    let created_a = a.generate_one_time_keys_with_rng(5, &mut seeded(4)).created;
    let created_b = b.generate_one_time_keys_with_rng(5, &mut seeded(4)).created;

    assert_eq!(created_a, created_b);
    assert_eq!(created_a.len(), 5);
    // Distinct RNG => distinct one-time keys.
    let created_c = b.generate_one_time_keys_with_rng(5, &mut seeded(7)).created;
    assert_ne!(created_a, created_c);
}

#[test]
fn generate_fallback_key_with_rng_is_deterministic() {
    let mut a = Account::new_with_rng(&mut seeded(5));
    let mut b = Account::new_with_rng(&mut seeded(5));

    a.generate_fallback_key_with_rng(&mut seeded(6));
    b.generate_fallback_key_with_rng(&mut seeded(6));

    assert_eq!(a.fallback_key(), b.fallback_key());
    assert!(!a.fallback_key().is_empty());
}

#[test]
fn outbound_session_and_first_message_with_rng_is_deterministic() {
    let build = || -> (String, OlmMessage) {
        let mut bob = Account::new_with_rng(&mut seeded(10));
        let bob_otk = *bob
            .generate_one_time_keys_with_rng(1, &mut seeded(11))
            .created
            .first()
            .expect("one OTK");

        let alice = Account::new_with_rng(&mut seeded(12));
        let mut session = alice
            .create_outbound_session_with_rng(
                SessionConfig::version_1(),
                bob.curve25519_key(),
                bob_otk,
                &mut seeded(13),
            )
            .expect("outbound session");

        let message = session.encrypt_with_rng("hello", &mut seeded(14)).expect("encrypt");
        (session.session_id(), message)
    };

    let (id1, msg1) = build();
    let (id2, msg2) = build();

    assert_eq!(id1, id2, "session id must be reproducible for identical inputs");
    assert_eq!(
        msg1.to_parts(),
        msg2.to_parts(),
        "ciphertext must be byte-identical for identical (state, seed, plaintext)"
    );
}

#[test]
fn with_rng_session_interoperates_with_default_account() {
    // Bob is built with the default (OsRng) path; Alice uses the `_with_rng`
    // path. If the seam is behaviour-preserving they must be able to talk.
    let mut bob = Account::new();
    let bob_otk =
        *bob.generate_one_time_keys(1).created.first().expect("one OTK");

    let alice = Account::new_with_rng(&mut seeded(20));
    let mut alice_session = alice
        .create_outbound_session_with_rng(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            bob_otk,
            &mut seeded(21),
        )
        .expect("outbound session");

    let message =
        alice_session.encrypt_with_rng("hello from with_rng", &mut seeded(22)).expect("encrypt");
    let OlmMessage::PreKey(prekey) = message else {
        panic!("first message must be a pre-key message");
    };

    let result = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &prekey)
        .expect("inbound session");
    assert_eq!(result.plaintext, b"hello from with_rng");

    // And the reply direction: default-built Bob replies, Alice decrypts.
    let mut bob_session = result.session;
    let reply = bob_session.encrypt("hi back").expect("encrypt");
    let plaintext = alice_session.decrypt(&reply).expect("alice decrypts reply");
    assert_eq!(plaintext, b"hi back");
}

/// Build a fully deterministic Alice session that has received one reply from
/// Bob, so its sending ratchet is *inactive*: the next `encrypt` performs a
/// genuine Diffie-Hellman ratchet advance and therefore consumes RNG bytes.
#[allow(clippy::expect_used, clippy::panic)]
fn alice_ready_to_advance() -> Session {
    let mut bob = Account::new_with_rng(&mut seeded(30));
    let bob_otk = *bob
        .generate_one_time_keys_with_rng(1, &mut seeded(31))
        .created
        .first()
        .expect("one OTK");

    let alice = Account::new_with_rng(&mut seeded(32));
    let mut alice_session = alice
        .create_outbound_session_with_rng(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            bob_otk,
            &mut seeded(33),
        )
        .expect("outbound session");

    let prekey = alice_session.encrypt_with_rng("hi", &mut seeded(34)).expect("encrypt");
    let OlmMessage::PreKey(prekey) = prekey else { panic!("expected pre-key message") };

    let mut bob_session = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), &prekey)
        .expect("inbound session")
        .session;

    // Bob replies; Alice decrypts, flipping her sending ratchet to inactive.
    let reply = bob_session.encrypt_with_rng("re", &mut seeded(35)).expect("encrypt");
    alice_session.decrypt(&reply).expect("alice decrypts reply");

    alice_session
}

#[test]
fn dh_ratchet_advance_is_reproducible_under_same_rng() {
    // Same session state + same advance RNG => byte-identical advancing message,
    // including the freshly minted ratchet public key embedded in the header.
    //
    // This is the load-bearing assertion for the encrypt seam: it pins that the
    // *caller's* RNG (not a fresh internal `rng()`) drives the DH-ratchet mint.
    // If `encrypt_with_rng` ever fell back to `OsRng`, this test would fail
    // (whereas the distinct-RNG test below would still pass).
    let mut a = alice_ready_to_advance();
    let mut b = alice_ready_to_advance();

    let msg_a = a.encrypt_with_rng("advance", &mut seeded(40)).expect("encrypt");
    let msg_b = b.encrypt_with_rng("advance", &mut seeded(40)).expect("encrypt");

    assert_eq!(msg_a.to_parts(), msg_b.to_parts());
}

#[test]
fn dh_ratchet_advance_mints_fresh_ephemeral_under_distinct_rng() {
    // Same session state, *different* advance RNG => the two genuinely-new DH
    // steps produce distinct advancing messages (distinct ephemeral ratchet
    // keys). This shows the advancing output is not frozen and responds to the
    // supplied RNG. Note: on its own this would also pass if the mint ignored
    // the caller's RNG and drew from OsRng — it is the reproducibility test
    // above that pins the caller's RNG as the actual entropy source. Together
    // they show a genuinely-new ratchet step is both driven by and fully
    // determined by the supplied RNG, which is why reusing an RNG state across
    // two distinct advancing steps would collapse the ephemeral (the documented
    // forward-secrecy footgun).
    let mut a = alice_ready_to_advance();
    let mut b = alice_ready_to_advance();

    let msg_a = a.encrypt_with_rng("advance", &mut seeded(40)).expect("encrypt");
    let msg_b = b.encrypt_with_rng("advance", &mut seeded(41)).expect("encrypt");

    assert_ne!(msg_a.to_parts(), msg_b.to_parts());
}
