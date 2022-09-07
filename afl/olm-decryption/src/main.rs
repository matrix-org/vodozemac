use afl::fuzz;
use vodozemac::olm::{Account, PreKeyMessage, SessionConfig};

fn main() {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);

    let mut session = alice.create_outbound_session(
        SessionConfig::version_2(),
        bob.curve25519_key(),
        *bob.one_time_keys().values().next().unwrap(),
    );

    fuzz!(|data: &[u8]| {
        if let Ok(message) = PreKeyMessage::try_from(data) {
            let message = message.into();
            let _ = session.decrypt(&message);
        }
    });
}
