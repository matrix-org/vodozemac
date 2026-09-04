//! Benchmarks for the common Olm operations.
//!
//! Every benchmark is a group with a `vodozemac` and an `olm-rs` member, so
//! that the two implementations can be compared directly. The `olm-rs` side is
//! the [`olm_rs`] crate, which binds the C libolm library, so its measurements
//! cover the bindings and libolm together.
//!
//! Where an operation needs a counterpart (an account to talk to, a message to
//! decrypt), both implementations are given the same input: the keys and the
//! ciphertexts are produced once, up front, and shared between the two members
//! of a group.
//!
//! The libolm API that `olm-rs` exposes is string based, so the `olm-rs`
//! measurements include the base64 decoding of the keys and ciphertexts it is
//! handed. For the operations benchmarked here that overhead is negligible next
//! to the cryptographic work.

#![allow(clippy::expect_used, missing_docs)]

use assert_matches2::assert_let;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use olm_rs::{
    PicklingMode,
    account::OlmAccount,
    session::{OlmMessage as OlmRsMessage, OlmSession, PreKeyMessage as OlmRsPreKeyMessage},
};
use vodozemac::{
    Curve25519PublicKey,
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
};

/// The plaintext that gets encrypted in all encryption benchmarks.
const MESSAGE: &str = "It's a secret to everybody";

/// The key that the pickles in the benchmark setup are encrypted with.
const PICKLE_KEY: [u8; 32] = [0u8; 32];

/// The number of one-time keys the key generation benchmark creates.
const ONE_TIME_KEY_COUNT: usize = 100;

/// The pickling mode matching [`PICKLE_KEY`].
///
/// [`PicklingMode`] isn't `Clone` and takes ownership of the key, so it needs
/// to be built anew for every olm-rs pickling call.
fn olm_rs_pickling_mode() -> PicklingMode {
    PicklingMode::Encrypted { key: PICKLE_KEY.to_vec() }
}

/// The published keys of an account someone can create an outbound session to.
struct PublishedKeys {
    identity_key: Curve25519PublicKey,
    one_time_key: Curve25519PublicKey,
}

impl PublishedKeys {
    /// The same keys in the base64 encoded form olm-rs expects.
    fn to_base64(&self) -> (String, String) {
        (self.identity_key.to_base64(), self.one_time_key.to_base64())
    }
}

/// Create an olm-rs account with a single published one-time key and return its
/// published keys.
///
/// The account itself is dropped, only the keys of the recipient are needed to
/// create an outbound session to it.
fn published_keys() -> PublishedKeys {
    let bob = OlmAccount::new();
    bob.generate_one_time_keys(1);

    let one_time_key = bob
        .parsed_one_time_keys()
        .curve25519()
        .values()
        .next()
        .cloned()
        .expect("Bob should have at least one one-time key");

    let identity_key = bob.parsed_identity_keys().curve25519().to_owned();

    PublishedKeys {
        identity_key: Curve25519PublicKey::from_base64(&identity_key)
            .expect("olm-rs should give us a valid Curve25519 identity key"),
        one_time_key: Curve25519PublicKey::from_base64(&one_time_key)
            .expect("olm-rs should give us a valid Curve25519 one-time key"),
    }
}

/// Convert a vodozemac pre-key message into the olm-rs representation.
fn to_olm_rs_pre_key_message(message: &OlmMessage) -> OlmRsPreKeyMessage {
    assert_let!(OlmMessage::PreKey(message) = message);

    let message = OlmRsMessage::from_type_and_ciphertext(0, message.to_base64())
        .expect("We should be able to create an olm-rs pre-key message");

    assert_let!(OlmRsMessage::PreKey(message) = message);

    message
}

/// Create an established pair of vodozemac sessions, the first one belonging to
/// the sender, the second one to the receiver.
fn vodozemac_session_pair() -> (Session, Session) {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);

    let identity_key = bob.curve25519_key();
    let one_time_key = bob
        .one_time_keys()
        .into_values()
        .next()
        .expect("Bob should have at least one one-time key");

    bob.mark_keys_as_published();

    let mut alice_session = alice
        .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
        .expect("We should be able to create an outbound session");

    let message =
        alice_session.encrypt(MESSAGE).expect("We should be able to encrypt a pre-key message");

    assert_let!(OlmMessage::PreKey(pre_key_message) = &message);

    let result = bob
        .create_inbound_session(SessionConfig::version_1(), alice.curve25519_key(), pre_key_message)
        .expect("We should be able to create an inbound session from the pre-key message");

    (alice_session, result.session)
}

/// Create an established session pair where the sender is a vodozemac session
/// and the receiver an olm-rs one.
///
/// Using vodozemac for the sending side in both session pairs keeps the
/// benchmarked receiving side as the only difference between the two.
fn olm_rs_session_pair() -> (Session, OlmSession) {
    let alice = Account::new();
    let bob = OlmAccount::new();

    bob.generate_one_time_keys(1);

    let keys = {
        let one_time_key = bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .next()
            .cloned()
            .expect("Bob should have at least one one-time key");
        let identity_key = bob.parsed_identity_keys().curve25519().to_owned();

        PublishedKeys {
            identity_key: Curve25519PublicKey::from_base64(&identity_key)
                .expect("olm-rs should give us a valid Curve25519 identity key"),
            one_time_key: Curve25519PublicKey::from_base64(&one_time_key)
                .expect("olm-rs should give us a valid Curve25519 one-time key"),
        }
    };

    bob.mark_keys_as_published();

    let mut alice_session = alice
        .create_outbound_session(SessionConfig::version_1(), keys.identity_key, keys.one_time_key)
        .expect("We should be able to create an outbound session");

    let message =
        alice_session.encrypt(MESSAGE).expect("We should be able to encrypt a pre-key message");

    let bob_session = bob
        .create_inbound_session_from(
            &alice.curve25519_key().to_base64(),
            to_olm_rs_pre_key_message(&message),
        )
        .expect("olm-rs should be able to create an inbound session from the pre-key message");

    (alice_session, bob_session)
}

/// Benchmark how long it takes to create a new Olm account.
pub fn account_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Creating an account");

    group.bench_function("vodozemac", |b| b.iter(Account::new));
    group.bench_function("olm-rs", |b| b.iter(OlmAccount::new));

    group.finish();
}

/// Benchmark how long it takes to generate a batch of one-time keys.
pub fn one_time_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generating one-time keys");

    group.bench_function("vodozemac", |b| {
        b.iter_batched_ref(
            Account::new,
            |account| account.generate_one_time_keys(ONE_TIME_KEY_COUNT),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("olm-rs", |b| {
        b.iter_batched_ref(
            OlmAccount::new,
            |account| account.generate_one_time_keys(ONE_TIME_KEY_COUNT),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to sign a message with the account's Ed25519
/// key.
pub fn signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signing a message");

    let account = Account::new();
    let olm_rs_account = OlmAccount::new();

    group.bench_function("vodozemac", |b| b.iter(|| account.sign(MESSAGE)));
    group.bench_function("olm-rs", |b| b.iter(|| olm_rs_account.sign(MESSAGE)));

    group.finish();
}

/// Benchmark how long it takes to pickle an account holding
/// [`ONE_TIME_KEY_COUNT`] one-time keys.
pub fn account_pickling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Pickling an account");

    let mut account = Account::new();
    account.generate_one_time_keys(ONE_TIME_KEY_COUNT);

    let olm_rs_account = OlmAccount::new();
    olm_rs_account.generate_one_time_keys(ONE_TIME_KEY_COUNT);

    group.bench_function("vodozemac", |b| b.iter(|| account.pickle().encrypt(&PICKLE_KEY)));

    group.bench_function("olm-rs", |b| {
        b.iter_batched(
            olm_rs_pickling_mode,
            |mode| olm_rs_account.pickle(mode),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to restore an account holding
/// [`ONE_TIME_KEY_COUNT`] one-time keys from a pickle.
pub fn account_unpickling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Unpickling an account");

    let mut account = Account::new();
    account.generate_one_time_keys(ONE_TIME_KEY_COUNT);
    let pickle = account.pickle().encrypt(&PICKLE_KEY);

    let olm_rs_account = OlmAccount::new();
    olm_rs_account.generate_one_time_keys(ONE_TIME_KEY_COUNT);
    let olm_rs_pickle = olm_rs_account.pickle(olm_rs_pickling_mode());

    group.bench_function("vodozemac", |b| {
        b.iter(|| {
            let pickle = AccountPickle::from_encrypted(&pickle, &PICKLE_KEY)
                .expect("We should be able to decrypt the account pickle");

            Account::from_pickle(pickle)
        });
    });

    group.bench_function("olm-rs", |b| {
        b.iter_batched(
            || (olm_rs_pickle.clone(), olm_rs_pickling_mode()),
            |(pickle, mode)| {
                OlmAccount::unpickle(pickle, mode)
                    .expect("olm-rs should be able to decrypt the account pickle")
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to create a 1-to-1 Olm session.
pub fn outbound_session_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Creating an outbound session");

    let keys = published_keys();
    let (identity_key, one_time_key) = keys.to_base64();

    group.bench_function("vodozemac", |b| {
        b.iter_batched(
            Account::new,
            |alice| {
                alice
                    .create_outbound_session(
                        SessionConfig::version_1(),
                        keys.identity_key,
                        keys.one_time_key,
                    )
                    .expect("We should be able to create an outbound session")
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("olm-rs", |b| {
        b.iter_batched(
            OlmAccount::new,
            |alice| {
                alice
                    .create_outbound_session(&identity_key, &one_time_key)
                    .expect("olm-rs should be able to create an outbound session")
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to create a 1-to-1 Olm session from a pre-key
/// message.
pub fn inbound_session_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Creating an inbound session");

    let alice = Account::new();
    let alice_identity_key = alice.curve25519_key();

    // The vodozemac side: a vodozemac account receiving a pre-key message.
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);

    let one_time_key = bob
        .one_time_keys()
        .into_values()
        .next()
        .expect("Bob should have at least one one-time key");
    let identity_key = bob.curve25519_key();

    bob.mark_keys_as_published();

    let mut alice_session = alice
        .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
        .expect("We should be able to create an outbound session");
    let message =
        alice_session.encrypt(MESSAGE).expect("We should be able to encrypt a pre-key message");

    assert_let!(OlmMessage::PreKey(pre_key_message) = &message);

    let bob_pickle = bob.pickle().encrypt(&PICKLE_KEY);

    // The olm-rs side: an olm-rs account receiving a pre-key message from the
    // same vodozemac sender.
    let olm_rs_bob = OlmAccount::new();
    olm_rs_bob.generate_one_time_keys(1);

    let olm_rs_keys = {
        let one_time_key = olm_rs_bob
            .parsed_one_time_keys()
            .curve25519()
            .values()
            .next()
            .cloned()
            .expect("Bob should have at least one one-time key");
        let identity_key = olm_rs_bob.parsed_identity_keys().curve25519().to_owned();

        PublishedKeys {
            identity_key: Curve25519PublicKey::from_base64(&identity_key)
                .expect("olm-rs should give us a valid Curve25519 identity key"),
            one_time_key: Curve25519PublicKey::from_base64(&one_time_key)
                .expect("olm-rs should give us a valid Curve25519 one-time key"),
        }
    };

    olm_rs_bob.mark_keys_as_published();

    let mut olm_rs_alice_session = alice
        .create_outbound_session(
            SessionConfig::version_1(),
            olm_rs_keys.identity_key,
            olm_rs_keys.one_time_key,
        )
        .expect("We should be able to create an outbound session");
    let olm_rs_message = olm_rs_alice_session
        .encrypt(MESSAGE)
        .expect("We should be able to encrypt a pre-key message");
    let olm_rs_pre_key_message = to_olm_rs_pre_key_message(&olm_rs_message);

    let olm_rs_bob_pickle = olm_rs_bob.pickle(olm_rs_pickling_mode());
    let alice_identity_key_base64 = alice_identity_key.to_base64();

    group.bench_function("vodozemac", |b| {
        b.iter_batched(
            || {
                let bob_pickle = AccountPickle::from_encrypted(&bob_pickle, &PICKLE_KEY)
                    .expect("We should be able to decrypt Bob's pickle");

                Account::from_pickle(bob_pickle)
            },
            |mut bob| {
                bob.create_inbound_session(
                    SessionConfig::version_1(),
                    alice_identity_key,
                    pre_key_message,
                )
                .expect("We should be able to decrypt the pre-key message and create a Session")
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("olm-rs", |b| {
        b.iter_batched(
            || {
                let bob = OlmAccount::unpickle(olm_rs_bob_pickle.clone(), olm_rs_pickling_mode())
                    .expect("olm-rs should be able to decrypt Bob's pickle");

                (bob, olm_rs_pre_key_message.clone())
            },
            |(bob, pre_key_message)| {
                bob.create_inbound_session_from(&alice_identity_key_base64, pre_key_message)
                    .expect("olm-rs should be able to create a Session from the pre-key message")
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark how long it takes to encrypt a message using a 1-to-1 Olm session.
pub fn encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encrypting a message");

    let keys = published_keys();
    let (identity_key, one_time_key) = keys.to_base64();

    let alice = Account::new();
    let mut session = alice
        .create_outbound_session(SessionConfig::version_1(), keys.identity_key, keys.one_time_key)
        .expect("We should be able to create an outbound session");

    let olm_rs_alice = OlmAccount::new();
    let olm_rs_session = olm_rs_alice
        .create_outbound_session(&identity_key, &one_time_key)
        .expect("olm-rs should be able to create an outbound session");

    group.bench_function("vodozemac", |b| {
        b.iter(|| session.encrypt(MESSAGE).expect("We should be able to encrypt a message"));
    });

    group.bench_function("olm-rs", |b| b.iter(|| olm_rs_session.encrypt(MESSAGE)));

    group.finish();
}

/// Benchmark how long it takes to decrypt a message using a 1-to-1 Olm session.
pub fn decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypting a message");

    // Decryption advances the receiving chain, so the session gets restored
    // from a pickle before every iteration and always decrypts the same
    // message.
    let (mut alice_session, bob_session) = vodozemac_session_pair();
    let message =
        alice_session.encrypt(MESSAGE).expect("We should be able to encrypt another message");
    let bob_pickle = bob_session.pickle().encrypt(&PICKLE_KEY);

    let (mut olm_rs_alice_session, olm_rs_bob_session) = olm_rs_session_pair();
    let olm_rs_message = olm_rs_alice_session
        .encrypt(MESSAGE)
        .expect("We should be able to encrypt another message");
    let olm_rs_message = OlmRsMessage::PreKey(to_olm_rs_pre_key_message(&olm_rs_message));
    let olm_rs_bob_pickle = olm_rs_bob_session.pickle(olm_rs_pickling_mode());

    group.bench_function("vodozemac", |b| {
        b.iter_batched_ref(
            || {
                let pickle = SessionPickle::from_encrypted(&bob_pickle, &PICKLE_KEY)
                    .expect("We should be able to decrypt Bob's session pickle");

                Session::from_pickle(pickle)
            },
            |session| {
                let plaintext =
                    session.decrypt(&message).expect("We should be able to decrypt the message");

                assert_eq!(plaintext, MESSAGE.as_bytes());
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("olm-rs", |b| {
        b.iter_batched(
            || {
                let session =
                    OlmSession::unpickle(olm_rs_bob_pickle.clone(), olm_rs_pickling_mode())
                        .expect("olm-rs should be able to decrypt Bob's session pickle");

                (session, olm_rs_message.clone())
            },
            |(session, message)| {
                let plaintext =
                    session.decrypt(message).expect("olm-rs should be able to decrypt the message");

                assert_eq!(plaintext, MESSAGE);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    account_creation,
    one_time_key_generation,
    signing,
    account_pickling,
    account_unpickling,
    outbound_session_creation,
    inbound_session_creation,
    encryption,
    decryption
);
criterion_main!(benches);
