//! Benchmark for the common Megolm operations.

#![allow(clippy::expect_used, missing_docs)]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use vodozemac::megolm::{GroupSession, InboundGroupSession, SessionConfig};

/// Benchmark how long it takes to create a 1-to-1 Olm session.
pub fn outbound_session_creation(c: &mut Criterion) {
    c.bench_function("Creating an outbound session", |b| {
        b.iter(|| GroupSession::new(SessionConfig::version_1()));
    });
}

/// Benchmark how long it takes encrypt a message using a Megolm session.
pub fn encryption(c: &mut Criterion) {
    // TODO: Compare `SessionConfig` v1 and v2.
    let mut session = GroupSession::new(SessionConfig::version_1());

    c.bench_function("Encrypting a message", |b| {
        b.iter(|| session.encrypt("It's a secret to everybody"));
    });
}

/// Benchmark how long it takes decrypt a message using a Megolm session.
pub fn decryption(c: &mut Criterion) {
    // TODO: Compare `SessionConfig` v1 and v2.
    let mut session = GroupSession::new(SessionConfig::version_1());

    c.bench_function("Decrypting a message", |b| {
        b.iter_batched(
            || {
                let inbound_session =
                    InboundGroupSession::new(&session.session_key(), SessionConfig::version_1());
                (inbound_session, session.encrypt("It's a secret to everybody"))
            },
            |(mut session, message)| {
                let result =
                    session.decrypt(&message).expect("We should be able to decrypt the message");

                assert_eq!(result.plaintext, b"It's a secret to everybody");
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, outbound_session_creation, encryption, decryption);
criterion_main!(benches);
