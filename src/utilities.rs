pub use base64::DecodeError;
use base64::{decode_config, encode_config, STANDARD_NO_PAD};
use std::io::{Cursor, Read, Seek, SeekFrom};
use x25519_dalek::StaticSecret as Curve25519SecretKey;

/// Decode the input as base64 with no padding.
pub fn base64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, STANDARD_NO_PAD)
}

/// Encode the input as base64 with no padding.
pub fn base64_encode(input: impl AsRef<[u8]>) -> String {
    encode_config(input, STANDARD_NO_PAD)
}

// The integer encoding logic here has been taken from the integer-encoding[1]
// crate and is under the MIT license.
//
// The MIT License (MIT)
//
// Copyright (c) 2016 Google Inc. (lewinb@google.com) -- though not an official
// Google product or in any way related!
// Copyright (c) 2018-2020 Lewin Bormann (lbo@spheniscida.de)
//
// [1]: https://github.com/dermesser/integer-encoding-rs
pub(crate) trait VarInt {
    fn to_var_int(self) -> Vec<u8>;
}

/// Most-significant byte, == 0x80
const MSB: u8 = 0b1000_0000;

/// How many bytes an integer uses when being encoded as a VarInt.
#[inline]
fn required_encoded_space_unsigned(mut v: u64) -> usize {
    if v == 0 {
        return 1;
    }

    let mut logcounter = 0;
    while v > 0 {
        logcounter += 1;
        v >>= 7;
    }
    logcounter
}

impl VarInt for usize {
    fn to_var_int(self) -> Vec<u8> {
        (self as u64).to_var_int()
    }
}

impl VarInt for u32 {
    fn to_var_int(self) -> Vec<u8> {
        (self as u64).to_var_int()
    }
}

impl VarInt for u64 {
    #[inline]
    fn to_var_int(self) -> Vec<u8> {
        let mut v = Vec::new();
        v.resize(required_encoded_space_unsigned(self), 0);

        let mut n = self;
        let mut i = 0;

        while n >= 0x80 {
            v[i] = MSB | (n as u8);
            i += 1;
            n >>= 7;
        }

        v[i] = n as u8;

        v
    }
}

pub(crate) fn read_u32(cursor: &mut Cursor<Vec<u8>>) -> std::io::Result<u32> {
    let mut num = [0u8; 4];
    cursor.read_exact(&mut num)?;
    Ok(u32::from_be_bytes(num))
}

pub(crate) fn read_curve_key(cursor: &mut Cursor<Vec<u8>>) -> std::io::Result<Curve25519SecretKey> {
    // Skip the public key.
    cursor.seek(SeekFrom::Current(32))?;
    let mut private_key = [0u8; 32];
    cursor.read_exact(&mut private_key)?;

    Ok(Curve25519SecretKey::from(private_key))
}

pub(crate) fn read_bool(cursor: &mut Cursor<Vec<u8>>) -> std::io::Result<bool> {
    let mut published = [0u8; 1];
    cursor.read_exact(&mut published).unwrap();
    Ok(published[0] != 0)
}
