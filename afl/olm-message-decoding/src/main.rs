#[cfg(fuzzing)]
use afl::fuzz;
use vodozemac::olm::PreKeyMessage;

#[cfg(fuzzing)]
fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(decoded) = PreKeyMessage::try_from(data.to_vec()) {
            let encoded = decoded.to_bytes();
            let re_decoded =
                PreKeyMessage::try_from(encoded).expect("Re-encoding should always work");
            assert_eq!(decoded, re_decoded);
        }
    });
}

#[cfg(not(fuzzing))]
use clap::Parser;

/// Search for a pattern in a file and display the lines that contain it.
#[cfg(not(fuzzing))]
#[derive(Parser)]
struct Cli {
    /// The path to the file to read
    #[clap(parse(from_os_str))]
    path: std::path::PathBuf,
}

#[cfg(not(fuzzing))]
fn main() {
    let args = Cli::parse();

    let contents = std::fs::read(args.path).expect("Something went wrong reading the file");

    let message =
        PreKeyMessage::try_from(contents.clone()).expect("Couldn't parse the pre-key message");

    println!("Successfully parsed a message {:#?}", message);

    let encoded = message.to_bytes();
    let decoded =
        PreKeyMessage::try_from(encoded).expect("A re-encoded message can always be decoded");

    assert_eq!(message, decoded);
}
