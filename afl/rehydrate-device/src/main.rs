use afl::fuzz;
use vodozemac::olm::Account;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = Account::from_decrypted_dehydrated_device(data);
    });
}
