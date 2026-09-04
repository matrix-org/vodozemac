//! Benchmarks for the common Megolm operations.
//!
//! Every benchmark is a group with a `vodozemac` and a `libolm` member, so that
//! the two implementations can be compared directly. The `libolm` side is
//! driven through the [`olm_rs`] bindings.
//!
//! The libolm API is string based, so the `libolm` measurements include the
//! base64 decoding of the keys and ciphertexts it is handed. For the operations
//! benchmarked here that overhead is negligible next to the cryptographic work.

#![allow(clippy::expect_used, missing_docs)]

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use olm_rs::{
    PicklingMode, inbound_group_session::OlmInboundGroupSession,
    outbound_group_session::OlmOutboundGroupSession,
};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, SessionConfig, SessionKey,
};

/// The plaintext that gets encrypted in all encryption benchmarks.
const MESSAGE: &str = "It's a secret to everybody";

/// The key that the pickles in the benchmark setup are encrypted with.
const PICKLE_KEY: [u8; 32] = [0u8; 32];

/// The pickling mode matching [`PICKLE_KEY`].
///
/// [`PicklingMode`] isn't `Clone` and takes ownership of the key, so it needs
/// to be built anew for every libolm pickling call.
fn libolm_pickling_mode() -> PicklingMode {
    PicklingMode::Encrypted { key: PICKLE_KEY.to_vec() }
}

/// Benchmark how long it takes to create an outbound Megolm session.
pub fn outbound_session_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Creating an outbound session");

    // TODO: Compare `SessionConfig` v1 and v2.
    group.bench_function("vodozemac", |b| {
        b.iter(|| GroupSession::new(SessionConfig::version_1()));
    });

    group.bench_function("libolm", |b| b.iter(OlmOutboundGroupSession::new));

    group.finish();
}

/// Benchmark how long it takes to create an inbound Megolm session from a
/// session key.
///
/// Both implementations start from the base64 encoded session key, since libolm
/// decodes and verifies the session key as part of the session creation while
/// vodozemac does so when the [`SessionKey`] is decoded.
pub fn inbound_session_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Creating an inbound session");

    // Both implementations import the same session key, exported by a vodozemac
    // outbound session.
    let session = GroupSession::new(SessionConfig::version_1());
    let session_key_base64 = session.session_key().to_base64();

    group.bench_function("vodozemac", |b| {
        b.iter(|| {
            let session_key = SessionKey::from_base64(&session_key_base64)
                .expect("We should be able to decode the session key");

            InboundGroupSession::new(&session_key, SessionConfig::version_1())
        });
    });

    group.bench_function("libolm", |b| {
        b.iter(|| {
            OlmInboundGroupSession::new(&session_key_base64)
                .expect("libolm should be able to import the session key")
        });
    });

    group.finish();
}

/// Benchmark how long it takes to encrypt a message using a Megolm session.
pub fn encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encrypting a message");

    // TODO: Compare `SessionConfig` v1 and v2.
    let mut session = GroupSession::new(SessionConfig::version_1());
    let libolm_session = OlmOutboundGroupSession::new();

    group.bench_function("vodozemac", |b| b.iter(|| session.encrypt(MESSAGE)));
    group.bench_function("libolm", |b| b.iter(|| libolm_session.encrypt(MESSAGE)));

    group.finish();
}

/// Benchmark how long it takes to decrypt a message using a Megolm session.
pub fn decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypting a message");

    // Decryption advances the ratchet, so both sides get a session that is
    // freshly imported at the message index of the message they decrypt.
    let mut session = GroupSession::new(SessionConfig::version_1());
    let mut libolm_session = GroupSession::new(SessionConfig::version_1());

    // TODO: Compare `SessionConfig` v1 and v2.
    group.bench_function("vodozemac", |b| {
        b.iter_batched(
            || {
                let inbound_session =
                    InboundGroupSession::new(&session.session_key(), SessionConfig::version_1());

                (inbound_session, session.encrypt(MESSAGE))
            },
            |(mut session, message)| {
                let result =
                    session.decrypt(&message).expect("We should be able to decrypt the message");

                assert_eq!(result.plaintext, MESSAGE.as_bytes());
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("libolm", |b| {
        b.iter_batched(
            || {
                let inbound_session =
                    OlmInboundGroupSession::new(&libolm_session.session_key().to_base64())
                        .expect("libolm should be able to import the session key");

                (inbound_session, libolm_session.encrypt(MESSAGE).to_base64())
            },
            |(session, message)| {
                let (plaintext, _) =
                    session.decrypt(message).expect("libolm should be able to decrypt the message");

                assert_eq!(plaintext, MESSAGE);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to pickle an inbound Megolm session.
pub fn inbound_session_pickling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Pickling an inbound session");

    let session = GroupSession::new(SessionConfig::version_1());
    let session_key = session.session_key();
    let inbound_session = InboundGroupSession::new(&session_key, SessionConfig::version_1());
    let libolm_session = OlmInboundGroupSession::new(&session_key.to_base64())
        .expect("libolm should be able to import the session key");

    group.bench_function("vodozemac", |b| {
        b.iter(|| inbound_session.pickle().encrypt(&PICKLE_KEY));
    });

    group.bench_function("libolm", |b| {
        b.iter_batched(
            libolm_pickling_mode,
            |mode| libolm_session.pickle(mode),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to restore an outbound Megolm session from a
/// pickle.
pub fn outbound_session_unpickling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Unpickling an outbound session");

    let session = GroupSession::new(SessionConfig::version_1());
    let pickle = session.pickle().encrypt(&PICKLE_KEY);

    let libolm_session = OlmOutboundGroupSession::new();
    let libolm_pickle = libolm_session.pickle(libolm_pickling_mode());

    group.bench_function("vodozemac", |b| {
        b.iter(|| {
            let pickle = GroupSessionPickle::from_encrypted(&pickle, &PICKLE_KEY)
                .expect("We should be able to decrypt the session pickle");

            GroupSession::from_pickle(pickle)
        });
    });

    group.bench_function("libolm", |b| {
        b.iter_batched(
            || (libolm_pickle.clone(), libolm_pickling_mode()),
            |(pickle, mode)| {
                OlmOutboundGroupSession::unpickle(pickle, mode)
                    .expect("libolm should be able to decrypt the session pickle")
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    outbound_session_creation,
    inbound_session_creation,
    encryption,
    decryption,
    inbound_session_pickling,
    outbound_session_unpickling
);
criterion_main!(benches);
