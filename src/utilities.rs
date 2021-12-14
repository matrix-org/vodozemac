pub use base64::DecodeError;
use base64::{decode_config, encode_config, STANDARD_NO_PAD, URL_SAFE_NO_PAD};

/// Decode the input as base64 with no padding.
pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, STANDARD_NO_PAD)
}

/// Decode the input as URL safe base64 with no padding.
pub fn decode_url_safe(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, URL_SAFE_NO_PAD)
}

/// Encode the input as base64 with no padding.
pub fn encode(input: impl AsRef<[u8]>) -> String {
    encode_config(input, STANDARD_NO_PAD)
}

/// Encode the input as URL safe base64 with no padding.
pub fn encode_url_safe(input: impl AsRef<[u8]>) -> String {
    encode_config(input, URL_SAFE_NO_PAD)
}
