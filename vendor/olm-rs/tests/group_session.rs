use olm_rs::{
    errors, inbound_group_session::OlmInboundGroupSession,
    outbound_group_session::OlmOutboundGroupSession, PicklingMode,
};

#[test]
fn group_session_pickling_valid() {
    let ogs = OlmOutboundGroupSession::new();
    let ogs_id = ogs.session_id();
    // ID is valid base64?
    base64::decode(&ogs_id).unwrap();

    // no messages have been sent yet
    assert_eq!(0, ogs.session_message_index());

    let ogs_pickled = ogs.pickle(PicklingMode::Unencrypted);
    let ogs = OlmOutboundGroupSession::unpickle(ogs_pickled, PicklingMode::Unencrypted).unwrap();
    assert_eq!(ogs_id, ogs.session_id());

    let igs = OlmInboundGroupSession::new(&ogs.session_key()).unwrap();
    let igs_id = igs.session_id();
    // ID is valid base64?
    base64::decode(&igs_id).unwrap();

    // no messages have been sent yet
    assert_eq!(0, igs.first_known_index());

    let igs_pickled = igs.pickle(PicklingMode::Unencrypted);
    let igs = OlmInboundGroupSession::unpickle(igs_pickled, PicklingMode::Unencrypted).unwrap();
    assert_eq!(igs_id, igs.session_id());
}

#[test]
/// Send message from A to B
fn group_session_crypto_valid() {
    let ogs = OlmOutboundGroupSession::new();
    let igs = OlmInboundGroupSession::new(&ogs.session_key()).unwrap();

    assert_eq!(ogs.session_id(), igs.session_id());

    let plaintext = "Hello world!";
    let ciphertext = ogs.encrypt(plaintext);
    // ciphertext valid base64?
    base64::decode(&ciphertext).unwrap();

    let decryption_result = igs.decrypt(ciphertext).unwrap();

    // correct plaintext?
    assert_eq!(String::from("Hello world!"), decryption_result.0);

    // first message sent, so the message index is zero
    assert_eq!(0, decryption_result.1);
}

#[test]
fn group_session_decrypting_invalid_base64_returns_error() {
    let ogs = OlmOutboundGroupSession::new();
    let igs = OlmInboundGroupSession::new(&ogs.session_key()).unwrap();

    let invalid_ciphertext = "1".to_owned();
    assert_eq!(
        igs.decrypt(invalid_ciphertext),
        Err(errors::OlmGroupSessionError::InvalidBase64)
    );
}
