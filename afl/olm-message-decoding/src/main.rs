use afl::fuzz;
use vodozemac::fuzzing::DecodedPreKeyMessage;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(decoded) = DecodedPreKeyMessage::try_from(data.to_vec()) {
            decoded.message.source.as_payload_bytes();
        }
    });
}
