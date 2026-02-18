//! Benchmark for the common Olm operations.

#![allow(clippy::expect_used, missing_docs)]

use assert_matches2::assert_let;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, SessionConfig};

/// Benchmark how long it takes to create a 1-to-1 Olm session.
pub fn outbound_session_creation(c: &mut Criterion) {
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);

    let identity_key = bob.curve25519_key();
    let one_time_key = bob
        .one_time_keys()
        .into_values()
        .last()
        .expect("Bob should have at least one one-time key");

    bob.mark_keys_as_published();

    c.bench_function("Creating an outbound session", |b| {
        b.iter_batched(
            Account::new,
            |alice| {
                #[allow(clippy::unwrap_used)]
                alice
                    .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark how long it takes to encrypt a message using a 1-to-1 Olm session.
pub fn encryption(c: &mut Criterion) {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);

    let identity_key = bob.curve25519_key();
    let one_time_key = bob
        .one_time_keys()
        .into_values()
        .last()
        .expect("Bob should have at least one one-time key");

    bob.mark_keys_as_published();

    #[allow(clippy::unwrap_used)]
    let mut session = alice
        .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
        .unwrap();

    c.bench_function("Encrypting a message", |b| {
        b.iter(|| {
            #[allow(clippy::unwrap_used)]
            session.encrypt("It's a secret to everybody").unwrap()
        });
    });
}

/// Benchmark how long it takes to create a 1-to-1 Olm session from a pre-key
/// message.
pub fn inbound_session_creation(c: &mut Criterion) {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);

    let identity_key = bob.curve25519_key();
    let one_time_key = bob
        .one_time_keys()
        .into_values()
        .last()
        .expect("Bob should have at least one one-time key");

    bob.mark_keys_as_published();

    #[allow(clippy::unwrap_used)]
    let mut session = alice
        .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
        .unwrap();

    #[allow(clippy::unwrap_used)]
    let pre_key_message = session.encrypt("It's a secret to everybody").unwrap();
    assert_let!(OlmMessage::PreKey(pre_key_message) = pre_key_message);

    let bob_pickle = bob.pickle().encrypt(&[0u8; 32]);
    let identity_key = alice.curve25519_key();

    c.bench_function("Creating an inbound session", |b| {
        b.iter_batched(
            || {
                let bob_pickle = AccountPickle::from_encrypted(&bob_pickle, &[0u8; 32])
                    .expect("We should be able to decrypt Bob's pickle");
                Account::from_pickle(bob_pickle)
            },
            |mut bob| {
                bob.create_inbound_session(identity_key, &pre_key_message)
                    .expect("We should be able to decrypt the pre-key message and create a Session")
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, outbound_session_creation, encryption, inbound_session_creation);
criterion_main!(benches);
