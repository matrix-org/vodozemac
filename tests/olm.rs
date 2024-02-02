use assert_matches2::assert_let;
use vodozemac::olm::{Account, InboundCreationResult, OlmMessage, SessionConfig};

#[test]
fn inbound_session_creation_post_quantum() {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);
    bob.generate_fallback_key();
    bob.keys().kyber().generate(1);

    let one_time_keys = bob.one_time_keys();

    let one_time_key = one_time_keys
        .curve25519
        .values()
        .next()
        .cloned()
        .expect("Didn't find a valid one-time key");

    let signed_pre_key =
        bob.fallback_key().into_values().next().expect("Didn't find a valid fallback key");
    let (kyber_key_id, kyber_key) =
        one_time_keys.kyber.into_iter().next().expect("Didn't find a valid keyber one-time key");

    let session_config = SessionConfig::version_pq(
        bob.identity_keys().curve25519,
        signed_pre_key,
        Some(one_time_key),
        kyber_key,
        kyber_key_id,
    );
    let mut alice_session = alice.create_outbound_session(session_config);

    let text = "It's a secret to everybody";
    let message = alice_session.encrypt(text);

    assert_let!(OlmMessage::PqPreKey(message) = message);

    let InboundCreationResult { mut session, plaintext } = bob
        .create_inbound_session_pq(&message)
        .expect("We should be able to create a new inbound PQ session");

    assert_eq!(text.as_bytes(), plaintext.as_slice());

    let second_message = "Another secret";
    let second_encrypted = session.encrypt(second_message);

    let second_decrypted = alice_session
        .decrypt(&second_encrypted)
        .expect("We should be able to decrypt the second message");

    assert_eq!(second_message.as_bytes(), second_decrypted.as_slice());
}
