use afl::fuzz;
use vodozemac::megolm::{ExportedSessionKey, InboundGroupSession, SessionConfig};

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(key) = ExportedSessionKey::try_from(data) {
            let _session = InboundGroupSession::import(&key, SessionConfig::version_2());
        }
    });
}
