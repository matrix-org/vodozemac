use afl::fuzz;
use vodozemac::olm::{Account, OlmMessage};

fn main() {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);

    let mut session = alice.create_outbound_session(
        *bob.curve25519_key(),
        *bob.one_time_keys().values().next().unwrap(),
    );

    fuzz!(|data: &[u8]| {
        if let Ok(s) = String::from_utf8(data.to_vec()) {
            if let Some(message) = OlmMessage::from_parts(0, s) {
                let _ = session.decrypt(&message);
            }
        }
    });
}
