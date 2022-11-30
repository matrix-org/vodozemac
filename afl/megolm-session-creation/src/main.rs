use afl::fuzz;
use vodozemac::megolm::{InboundGroupSession, SessionConfig, SessionKey};

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(key) = SessionKey::try_from(data) {
            let _session = InboundGroupSession::new(&key, SessionConfig::version_1());
        }
    });
}
