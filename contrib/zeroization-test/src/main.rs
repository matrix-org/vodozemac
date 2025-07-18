use vodozemac::Ed25519SecretKey;

fn use_keys(_keys: Ed25519SecretKey) {
    println!("Point B. Using keys...");
}

fn main() {
    // Used for comparison from inside gdb, to ensure the buffer is zeroized.
    let _zero = [0u8; 32];

    let secret = [0xFFu8; 32];
    println!("Point A. Creating keys...");
    let keys = Ed25519SecretKey::from_slice(&secret);
    use_keys(keys);
    println!("Point C. `keys` was dropped so buffer should now be zeroized.")
}
