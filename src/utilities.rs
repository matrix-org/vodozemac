pub use base64::DecodeError;
use base64::{decode_config, encode_config, STANDARD_NO_PAD};

/// Decode the input as base64 with no padding.
pub fn base64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, STANDARD_NO_PAD)
}

/// Encode the input as base64 with no padding.
pub fn base64_encode(input: impl AsRef<[u8]>) -> String {
    encode_config(input, STANDARD_NO_PAD)
}
