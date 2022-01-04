use afl::fuzz;
use vodozemac::fuzzing::DecodedPreKeyMessage;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = DecodedPreKeyMessage::try_from(data.to_vec());
    });
}
