#[cfg(not(feature = "cli"))]
use afl::fuzz;

#[cfg(not(feature = "cli"))]
fn main() {
    fuzz!(|data: &[u8]| {
        let _ = vodozemac::olm::Account::from_decrypted_libolm_pickle(&data);
    });
}

#[cfg(feature = "cli")]
use clap::Parser;

#[cfg(feature = "cli")]
/// Parse an Olm account from a file and print its identity keys on success.
#[derive(Parser)]
struct Cli {
    /// The path to the file to read
    #[clap(parse(from_os_str))]
    path: std::path::PathBuf,
}

#[cfg(feature = "cli")]
fn main() {
    let args = Cli::parse();

    let contents = std::fs::read(args.path).expect("Something went wrong reading the file");

    let account = vodozemac::olm::Account::from_decrypted_libolm_pickle(&contents)
        .expect("Couldn't decode the account");

    println!("Successfully decoded an account {:#?}", account.identity_keys());
}
