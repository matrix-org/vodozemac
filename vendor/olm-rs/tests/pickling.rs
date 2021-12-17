use olm_rs::{
    account::OlmAccount,
    errors::{OlmAccountError, OlmSessionError},
    session::OlmSession,
    PicklingMode,
};

#[test]
fn account_pickling_fails_on_wrong_key() {
    let pickled;
    {
        let olm_account = OlmAccount::new();
        pickled = olm_account.pickle(PicklingMode::Encrypted {
            key: [3, 2, 1].to_vec(),
        });
    }
    // wrong key
    let olm_account_bad = OlmAccount::unpickle(
        pickled,
        PicklingMode::Encrypted {
            key: [1, 2, 3].to_vec(),
        },
    );

    assert!(olm_account_bad.is_err());
    assert_eq!(olm_account_bad.err(), Some(OlmAccountError::BadAccountKey));
}

#[test]
fn session_pickling_valid() {
    let pickled_account_a = String::from("eOBXIKivUT6YYowRH031BNv7zNmzqM5B7CpXdyeaPvala5mt7/OeqrG1qVA7vA1SYloFyvJPIy0QNkD3j1HiPl5vtZHN53rtfZ9exXDok03zjmssqn4IJsqcA7Fbo1FZeKafG0NFcWwCPTdmcV7REqxjqGm3I4K8MQFa45AdTGSUu2C12cWeOcbSMlcINiMral+Uyah1sgPmLJ18h1qcnskXUXQvpffZ5DiUw1Iz5zxnwOQF1GVyowPJD7Zdugvj75RQnDxAn6CzyvrY2k2CuedwqDC3fIXM2xdUNWttW4nC2g4InpBhCVvNwhZYxlUb5BUEjmPI2AB3dAL5ry6o9MFncmbN6x5x");
    let account_a = OlmAccount::unpickle(pickled_account_a, PicklingMode::Unencrypted).unwrap();
    let identity_key_b = "qIEr3TWcJQt4CP8QoKKJcCaukByIOpgh6erBkhLEa2o";
    let one_time_key_b = "WzsbsjD85iB1R32iWxfJdwkgmdz29ClMbJSJziECYwk";
    let outbound_session = account_a
        .create_outbound_session(identity_key_b, one_time_key_b)
        .unwrap();

    let session_id_before = outbound_session.session_id();
    let pickled_session = outbound_session.pickle(PicklingMode::Unencrypted);

    let outbound_session_unpickled =
        OlmSession::unpickle(pickled_session, PicklingMode::Unencrypted).unwrap();
    let session_id_after = outbound_session_unpickled.session_id();
    assert_eq!(session_id_before, session_id_after);
}

#[test]
fn session_pickling_fails_on_wrong_key() {
    let pickled_account_a = String::from("eOBXIKivUT6YYowRH031BNv7zNmzqM5B7CpXdyeaPvala5mt7/OeqrG1qVA7vA1SYloFyvJPIy0QNkD3j1HiPl5vtZHN53rtfZ9exXDok03zjmssqn4IJsqcA7Fbo1FZeKafG0NFcWwCPTdmcV7REqxjqGm3I4K8MQFa45AdTGSUu2C12cWeOcbSMlcINiMral+Uyah1sgPmLJ18h1qcnskXUXQvpffZ5DiUw1Iz5zxnwOQF1GVyowPJD7Zdugvj75RQnDxAn6CzyvrY2k2CuedwqDC3fIXM2xdUNWttW4nC2g4InpBhCVvNwhZYxlUb5BUEjmPI2AB3dAL5ry6o9MFncmbN6x5x");
    let account_a = OlmAccount::unpickle(pickled_account_a, PicklingMode::Unencrypted).unwrap();
    let identity_key_b = "qIEr3TWcJQt4CP8QoKKJcCaukByIOpgh6erBkhLEa2o";
    let one_time_key_b = "WzsbsjD85iB1R32iWxfJdwkgmdz29ClMbJSJziECYwk";
    let outbound_session = account_a
        .create_outbound_session(identity_key_b, one_time_key_b)
        .unwrap();
    let pickled_session = outbound_session.pickle(PicklingMode::Encrypted {
        key: [3, 2, 1].to_vec(),
    });

    // wrong key
    let outbound_session_bad = OlmSession::unpickle(
        pickled_session,
        PicklingMode::Encrypted {
            key: [1, 2, 3].to_vec(),
        },
    );
    assert!(outbound_session_bad.is_err());
    assert_eq!(
        outbound_session_bad.err(),
        Some(OlmSessionError::BadAccountKey)
    );
}
