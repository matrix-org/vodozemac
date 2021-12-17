use olm_rs::{account::OlmAccount, utility::OlmUtility};

#[test]
fn identity_keys_valid() {
    let olm_account = OlmAccount::new();
    let identity_keys = olm_account.parsed_identity_keys();
    let curve25519 = identity_keys.curve25519();
    let ed25519 = identity_keys.ed25519();
    // verify encoded keys length
    assert_eq!(curve25519.len(), 43);
    assert_eq!(ed25519.len(), 43);
    // encoded as valid base64?
    base64::decode(&curve25519).unwrap();
    base64::decode(&ed25519).unwrap();
}

#[test]
fn signatures_valid() {
    // test signature being valid base64
    let olm_account = OlmAccount::new();
    let message = "Hello world!".to_string();
    let signature = olm_account.sign(&message);
    base64::decode(&signature).unwrap();

    let utility = OlmUtility::new();
    let identity_keys = olm_account.parsed_identity_keys();
    let ed25519_key = identity_keys.ed25519();
    assert!(utility
        .ed25519_verify(ed25519_key, &message, signature)
        .unwrap());
}

#[test]
fn one_time_keys_valid() {
    let olm_account = OlmAccount::new();
    let max_number_otks = olm_account.max_number_of_one_time_keys();
    assert_eq!(100, max_number_otks);

    // empty read of one time keys
    let otks_empty = olm_account.parsed_one_time_keys();
    assert!(otks_empty.curve25519().is_empty());

    olm_account.generate_one_time_keys(20);
    let otks_filled = olm_account.parsed_one_time_keys();
    assert_eq!(20, otks_filled.curve25519().len());
    for (key, _) in otks_filled.curve25519().iter() {
        assert_eq!(6, key.len());
        base64::decode(&key).unwrap();
    }

    olm_account.mark_keys_as_published();

    // empty read of one time keys after marking as published
    let otks_empty = olm_account.parsed_one_time_keys();
    assert!(otks_empty.curve25519().is_empty());
}

#[test]
fn remove_one_time_keys() {
    let account_a = OlmAccount::new();
    account_a.generate_one_time_keys(1);

    let account_b = OlmAccount::new();
    account_b.generate_one_time_keys(1);

    let otks = account_b.parsed_one_time_keys();
    let identity_keys = account_b.parsed_identity_keys();
    let session = account_a
        .create_outbound_session(
            identity_keys.curve25519(),
            otks.curve25519().values().next().unwrap(),
        )
        .unwrap();

    assert_eq!(1, otks.curve25519().len());

    account_b.remove_one_time_keys(&session).unwrap();

    // empty read of one time keys after removing
    let otks_empty = account_b.parsed_one_time_keys();
    assert!(otks_empty.curve25519().is_empty());
}

#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value: BadMessageKeyId")]
fn remove_one_time_keys_fails() {
    let account_a = OlmAccount::new();
    account_a.generate_one_time_keys(1);

    let account_b = OlmAccount::new();
    account_b.generate_one_time_keys(1);

    let otks = account_b.parsed_one_time_keys();
    let identity_keys = account_b.parsed_identity_keys();
    let session = account_a
        .create_outbound_session(identity_keys.curve25519(), &otks.curve25519()["AAAAAQ"])
        .unwrap();

    assert_eq!(1, otks.curve25519().len());

    account_a.remove_one_time_keys(&session).unwrap();
}
