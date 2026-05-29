use afl::fuzz;
use vodozemac::hpke::InitialMessage;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(decoded) = InitialMessage::from_bytes(data) {
            let encoded = decoded.to_bytes();
            let re_decoded = InitialMessage::from_bytes(&encoded).expect("Re-decoding should always succeed");
            assert_eq!(decoded, re_decoded);
        }
    });
}
