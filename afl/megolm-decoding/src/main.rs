use afl::fuzz;
use vodozemac::megolm::MegolmMessage;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(decoded) = MegolmMessage::try_from(data) {
            let encoded = decoded.to_bytes();
            let re_decoded =
                MegolmMessage::try_from(encoded).expect("Re-encoding should always work");
            assert_eq!(decoded, re_decoded);
        }
    });
}
