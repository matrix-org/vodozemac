use vodozemac::cipher::key::ExpandedKeys;

fn use_keys(_keys: ExpandedKeys) {
    println!("Point B. Using keys...");
}

fn main() {
    // Used for comparison from inside gdb, to ensure the buffer is zeroized.
    let _zero: [u8; 80] = [0u8; 80];

    let secret: [u8; 32] = (0..32).collect::<Vec<_>>().try_into().unwrap();
    println!("Point A. Creating keys...");
    let keys = ExpandedKeys::new(&secret);
    use_keys(keys);
    println!("Point C. `keys` was dropped so buffer should now be zeroized.")
}
