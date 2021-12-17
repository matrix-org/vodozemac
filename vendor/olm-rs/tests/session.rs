use olm_rs::{
    account::OlmAccount,
    session::{OlmMessage, OlmSession},
    PicklingMode,
};

fn create_session_pair() -> (OlmSession, OlmSession) {
    let pickled_account_a = "eOBXIKivUT6YYowRH031BNv7zNmzqM5B7CpXdyeaPvala5mt7/OeqrG1qVA7vA1SYloFyvJPIy0QNkD3j1HiPl5vtZHN53rtfZ9exXDok03zjmssqn4IJsqcA7Fbo1FZeKafG0NFcWwCPTdmcV7REqxjqGm3I4K8MQFa45AdTGSUu2C12cWeOcbSMlcINiMral+Uyah1sgPmLJ18h1qcnskXUXQvpffZ5DiUw1Iz5zxnwOQF1GVyowPJD7Zdugvj75RQnDxAn6CzyvrY2k2CuedwqDC3fIXM2xdUNWttW4nC2g4InpBhCVvNwhZYxlUb5BUEjmPI2AB3dAL5ry6o9MFncmbN6x5x".to_string();
    let pickled_account_b = "eModTvoFi9oOIkax4j4nuxw9Tcl/J8mOmUctUWI68Q89HSaaPTqR+tdlKQ85v2GOs5NlZCp7EuycypN9GQ4fFbHUCrS7nspa3GFBWsR8PnM8+wez5PWmfFZLg3drOvT0jbMjpDx0MjGYClHBqcrEpKx9oFaIRGBaX6HXzT4lRaWSJkXxuX92q8iGNrLn96PuAWFNcD+2JXpPcNFntslwLUNgqzpZ04aIFYwL80GmzyOgq3Bz1GO6u3TgCQEAmTIYN2QkO0MQeuSfe7UoMumhlAJ6R8GPcdSSPtmXNk4tdyzzlgpVq1hm7ZLKto+g8/5Aq3PvnvA8wCqno2+Pi1duK1pZFTIlActr".to_string();
    let account_a = OlmAccount::unpickle(pickled_account_a, PicklingMode::Unencrypted).unwrap();
    let account_b = OlmAccount::unpickle(pickled_account_b, PicklingMode::Unencrypted).unwrap();
    let _identity_key_a = String::from("qIEr3TWcJQt4CP8QoKKJcCaukByIOpgh6erBkhLEa2o");
    let _one_time_key_a = String::from("WzsbsjD85iB1R32iWxfJdwkgmdz29ClMbJSJziECYwk");
    let identity_key_b = "q/YhJtog/5VHCAS9rM9uUf6AaFk1yPe4GYuyUOXyQCg";
    let one_time_key_b = "oWvzryma+B2onYjo3hM6A3Mgo/Yepm8HvgSvwZMTnjQ";
    let outbound = account_a
        .create_outbound_session(identity_key_b, one_time_key_b)
        .unwrap();
    let pre_key = outbound.encrypt(""); // Payload does not matter for PreKey

    let pre_key = if let OlmMessage::PreKey(m) = pre_key {
        m
    } else {
        panic!("Wrong first message type received, can't create session");
    };

    let inbound = account_b.create_inbound_session(pre_key).unwrap();
    (inbound, outbound)
}

#[test]
fn olm_outbound_session_creation() {
    let (_, outbound_session) = create_session_pair();
    assert!(!outbound_session.has_received_message());
}

#[test]
fn olm_encrypt_decrypt() {
    let (inbound_session, outbound_session) = create_session_pair();
    let encrypted = outbound_session.encrypt("Hello world!");
    if let OlmMessage::PreKey(m) = &encrypted {
        assert!(inbound_session.matches_inbound_session(m.clone()).unwrap());
    }

    let decrypted = inbound_session.decrypt(encrypted).unwrap();

    assert_eq!(decrypted, "Hello world!");
}

#[test]
fn correct_session_ordering() {
    // n0W5IJ2ZmaI9FxKRj/wohUQ6WEU0SfoKsgKKHsr4VbM
    let session_1 = OlmSession::unpickle("7g5cfQRsDk2ROXf9S01n2leZiFRon+EbvXcMOADU0UGvlaV6t/0ihD2/0QGckDIvbmE1aV+PxB0zUtHXh99bI/60N+PWkCLA84jEY4sz3d45ui/TVoFGLDHlymKxvlj7XngXrbtlxSkVntsPzDiNpKEXCa26N2ubKpQ0fbjrV5gbBTYWfU04DXHPXFDTksxpNALYt/h0eVMVhf6hB0ZzpLBsOG0mpwkLufwub0CuDEDGGmRddz3TcNCLq5NnI8R9udDWvHAkTS1UTbHuIf/y6cZg875nJyXpAvd8/XhL8TOo8ot2sE1fElBa4vrH/m9rBQMC1GPkhLBIizmY44C+Sq9PQRnF+uCZ".to_string(),PicklingMode::Unencrypted).unwrap();
    // +9pHJhP3K4E5/2m8PYBPLh8pS9CJodwUOh8yz3mnmw0
    let session_2 = OlmSession::unpickle("7g5cfQRsDk2ROXf9S01n2leZiFRon+EbvXcMOADU0UFD+q37/WlfTAzQsSjCdD07FcErZ4siEy5vpiB+pyO8i53ptZvb2qRvqNKFzPaXuu33PS2PBTmmnR+kJt+DgDNqWadyaj/WqEAejc7ALqSs5GuhbZtpoLe+lRSRK0rwVX3gzz4qrl8pm0pD5pSZAUWRXDRlieGWMclz68VUvnSaQH7ElTo4S634CJk+xQfFFCD26v0yONPSN6rwouS1cWPuG5jTlnV8vCFVTU2+lduKh54Ko6FUJ/ei4xR8Nk2duBGSc/TdllX9e2lDYHSUkWoD4ti5xsFioB8Blus7JK9BZfcmRmdlxIOD".to_string(),PicklingMode::Unencrypted).unwrap();
    // MC7n8hX1l7WlC2/WJGHZinMocgiBZa4vwGAOredb/ME
    let session_3 = OlmSession::unpickle("7g5cfQRsDk2ROXf9S01n2leZiFRon+EbvXcMOADU0UGNk2TmVDJ95K0Nywf24FNklNVtXtFDiFPHFwNSmCbHNCp3hsGtZlt0AHUkMmL48XklLqzwtVk5/v2RRmSKR5LqYdIakrtuK/fY0ENhBZIbI1sRetaJ2KMbY9l6rCJNfFg8VhpZ4KTVvEZVuP9g/eZkCnP5NxzXiBRF6nfY3O/zhcKxa3acIqs6BMhyLsfuJ80t+hQ1HvVyuhBerGujdSDzV9tJ9SPidOwfYATk81LVF9hTmnI0KaZa7qCtFzhG0dU/Z3hIWH9HOaw1aSB/IPmughbwdJOwERyhuo3YHoznlQnJ7X252BlI".to_string(),PicklingMode::Unencrypted).unwrap();

    let session_1_id = session_1.session_id();
    let session_2_id = session_2.session_id();
    let session_3_id = session_3.session_id();

    let mut session_list: Vec<OlmSession> = vec![session_1, session_2, session_3];

    session_list.sort_unstable();
    assert_eq!(session_list.get(0).unwrap().session_id(), session_2_id);
    assert_eq!(session_list.get(1).unwrap().session_id(), session_3_id);
    assert_eq!(session_list.get(2).unwrap().session_id(), session_1_id);
}
