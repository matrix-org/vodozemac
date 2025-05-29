// Copyright 2016 OpenMarket Ltd
// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use hmac::{Hmac, Mac as _};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Sha256, digest::CtOutput};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const ADVANCEMENT_SEEDS: [&[u8; 1]; Ratchet::RATCHET_PART_COUNT] =
    [b"\x00", b"\x01", b"\x02", b"\x03"];

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(super) struct Ratchet {
    inner: RatchetBytes,
    counter: u32,
}

impl ConstantTimeEq for Ratchet {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Short circuit on the counter, not on the contents of the ratchet.
        if self.counter != other.counter {
            Choice::from(0)
        } else {
            self.as_bytes().ct_eq(other.as_bytes())
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct RatchetBytes(Box<[u8; Ratchet::RATCHET_LENGTH]>);

impl RatchetBytes {
    fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetBytesError> {
        let length = bytes.len();

        if length != Ratchet::RATCHET_LENGTH {
            Err(RatchetBytesError::InvalidLength(length))
        } else {
            let mut ratchet = Self(Box::new([0u8; Ratchet::RATCHET_LENGTH]));
            ratchet.0.copy_from_slice(bytes);

            Ok(ratchet)
        }
    }
}

impl Serialize for RatchetBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = &self.0;
        bytes.serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for RatchetBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let mut bytes = <Vec<u8>>::deserialize(deserializer)?;
        let ratchet = Self::from_bytes(bytes.as_ref()).map_err(serde::de::Error::custom)?;

        bytes.zeroize();

        Ok(ratchet)
    }
}

struct RatchetPart<'a>(&'a mut [u8]);

impl RatchetPart<'_> {
    fn hash(&self, seed: &[u8; 1]) -> CtOutput<Hmac<Sha256>> {
        #[allow(clippy::expect_used)]
        let mut hmac = Hmac::<Sha256>::new_from_slice(self.0)
            .expect("We should be able to create a HMAC object from a ratchet part");
        hmac.update(seed);

        hmac.finalize()
    }

    fn update(&mut self, new_part: &[u8]) {
        self.0.copy_from_slice(new_part);
    }
}

struct RatchetParts<'a> {
    r_0: RatchetPart<'a>,
    r_1: RatchetPart<'a>,
    r_2: RatchetPart<'a>,
    r_3: RatchetPart<'a>,
}

impl<'a> RatchetParts<'a> {
    fn update(&'a mut self, from: usize, to: usize) {
        #[allow(clippy::unreachable)]
        let from = match from {
            0 => &self.r_0,
            1 => &self.r_1,
            2 => &self.r_2,
            3 => &self.r_3,
            _ => unreachable!("We only have 4 ratchet parts"),
        };

        let result = from.hash(ADVANCEMENT_SEEDS[to]);

        #[allow(clippy::unreachable)]
        let to = match to {
            0 => &mut self.r_0,
            1 => &mut self.r_1,
            2 => &mut self.r_2,
            3 => &mut self.r_3,
            _ => unreachable!("We only have 4 ratchet parts"),
        };

        to.update(&result.into_bytes());
    }
}

impl Ratchet {
    pub const RATCHET_LENGTH: usize = 128;
    const RATCHET_PART_COUNT: usize = 4;
    const LAST_RATCHET_INDEX: usize = Self::RATCHET_PART_COUNT - 1;

    pub fn new() -> Self {
        let mut rng = thread_rng();

        let mut ratchet =
            Self { inner: RatchetBytes(Box::new([0u8; Self::RATCHET_LENGTH])), counter: 0 };

        rng.fill_bytes(ratchet.inner.0.as_mut());

        ratchet
    }

    pub const fn from_bytes(bytes: Box<[u8; Self::RATCHET_LENGTH]>, counter: u32) -> Self {
        Self { inner: RatchetBytes(bytes), counter }
    }

    pub const fn index(&self) -> u32 {
        self.counter
    }

    pub const fn as_bytes(&self) -> &[u8; Self::RATCHET_LENGTH] {
        &self.inner.0
    }

    fn as_parts(&mut self) -> RatchetParts<'_> {
        let (top, bottom) = self.inner.0.split_at_mut(64);

        let (r_0, r_1) = top.split_at_mut(32);
        let (r_2, r_3) = bottom.split_at_mut(32);

        let r_0 = RatchetPart(r_0);
        let r_1 = RatchetPart(r_1);
        let r_2 = RatchetPart(r_2);
        let r_3 = RatchetPart(r_3);

        RatchetParts { r_0, r_1, r_2, r_3 }
    }

    pub fn advance(&mut self) {
        let mut mask: u32 = 0x00FFFFFF;

        // The index of the "slowest" part of the ratchet that needs to be
        // advanced.
        let mut h = 0;

        self.counter += 1;

        // Figure out which parts of the ratchet need to be advanced.
        while h < Self::RATCHET_PART_COUNT {
            if (self.counter & mask) == 0 {
                break;
            }

            h += 1;
            mask >>= 8;
        }

        let parts_to_advance = (h..=Self::LAST_RATCHET_INDEX).rev();

        // Now advance R(h)...R(3) based on R(h).
        for i in parts_to_advance {
            let mut parts = self.as_parts();
            parts.update(h, i);
        }
    }

    pub fn advance_to(&mut self, advance_to: u32) {
        for j in 0..Self::RATCHET_PART_COUNT {
            let shift = (Self::LAST_RATCHET_INDEX - j) * 8;
            let mask: u32 = !0u32 << shift;

            // How many times do we need to rehash this part? `& 0xff` ensures
            // we handle integer wrap-around correctly.
            let mut steps = ((advance_to >> shift) - (self.counter >> shift)) & 0xff;

            if steps == 0 {
                // Deal with the edge case where the ratchet counter is slightly
                // larger than the index we need to advance to. This should only
                // happen for R(0) and implies that advance_to has wrapped
                // around and we need to advance R(0) 256 times.
                if advance_to < self.counter {
                    steps = 0x100;
                } else {
                    continue;
                }
            }

            // For all but the last step, we can just bump R(j) without regard
            // to R(j+1)...R(3).
            while steps > 1 {
                let mut parts = self.as_parts();
                parts.update(j, j);
                steps -= 1;
            }

            // On the last step we also need to bump R(j+1)...R(3).
            // (Theoretically, we could skip bumping R(j+2) if we're going to
            // bump R(j+1) again, but the code to figure that out is a bit
            // baroque and doesn't save us much).

            let parts_to_update = (j..=Self::LAST_RATCHET_INDEX).rev();

            for k in parts_to_update {
                let mut parts = self.as_parts();
                parts.update(j, k);
            }

            self.counter = advance_to & mask;
        }
    }
}

#[derive(Error, Debug)]
enum RatchetBytesError {
    #[error("Invalid Megolm ratchet length: expected 128, got {0}")]
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advancing_high_counter_ratchet_doesnt_panic() {
        let mut ratchet = Ratchet::new();
        ratchet.counter = 0x00FFFFFF;
        ratchet.advance();
    }

    #[test]
    fn advance_to_with_high_counter_doesnt_panic() {
        let mut ratchet = Ratchet::new();
        ratchet.counter = (1 << 24) - 1;
        ratchet.advance_to(1 << 24);
    }

    #[test]
    fn advance_forward_and_back() {
        let mut ratchet = Ratchet::new();
        assert_eq!(ratchet.counter, 0);
        ratchet.advance();
        assert_eq!(ratchet.counter, 1);
        ratchet.advance();
        assert_eq!(ratchet.counter, 2);
        ratchet.advance_to(1);
        assert_eq!(ratchet.counter, 1);
    }

    #[test]
    #[should_panic]
    fn only_four_parts_are_available_for_an_update() {
        let mut ratchet = Ratchet::from_bytes([0; 128].into(), 0);
        let mut parts = ratchet.as_parts();

        // This panics, because the ratchet has only 4 parts, from 0 to 3.
        parts.update(0, 4);
    }

    #[test]
    fn update_modifies_the_correct_part() {
        let mut ratchet = Ratchet::from_bytes([0; 128].into(), 0);

        {
            let parts = ratchet.as_parts();

            // At the beginning we're all zero bytes.
            assert_eq!(parts.r_0.0, [0; 32]);
            assert_eq!(parts.r_1.0, [0; 32]);
            assert_eq!(parts.r_2.0, [0; 32]);
            assert_eq!(parts.r_3.0, [0; 32]);
        }

        {
            let mut parts = ratchet.as_parts();
            parts.update(0, 1);
        }

        {
            let parts = ratchet.as_parts();

            // Now we advanced the zeroth part and put the result into the first part.
            assert_eq!(parts.r_0.0, [0; 32]);
            assert_ne!(parts.r_1.0, [0; 32]);
            assert_eq!(parts.r_2.0, [0; 32]);
            assert_eq!(parts.r_3.0, [0; 32]);
        }

        {
            let mut parts = ratchet.as_parts();
            parts.update(1, 2);
        }

        {
            let parts = ratchet.as_parts();

            // Now we advanced the third part and put the result into the second part.
            assert_eq!(parts.r_0.0, [0; 32]);
            assert_ne!(parts.r_1.0, [0; 32]);
            assert_ne!(parts.r_2.0, [0; 32]);
            assert_eq!(parts.r_3.0, [0; 32]);
        }

        {
            let mut parts = ratchet.as_parts();
            parts.update(2, 3);
        }

        {
            let parts = ratchet.as_parts();

            // Now we advanced the second part and put the result into the zeroth part.
            assert_eq!(parts.r_0.0, [0; 32]);
            assert_ne!(parts.r_1.0, [0; 32]);
            assert_ne!(parts.r_2.0, [0; 32]);
            assert_ne!(parts.r_3.0, [0; 32]);
        }

        {
            let mut parts = ratchet.as_parts();
            parts.update(3, 0);
        }

        {
            let parts = ratchet.as_parts();

            // Now we advanced the second part and put the result into the zeroth part.
            assert_ne!(parts.r_0.0, [0; 32]);
            assert_ne!(parts.r_1.0, [0; 32]);
            assert_ne!(parts.r_2.0, [0; 32]);
            assert_ne!(parts.r_3.0, [0; 32]);
        }
    }
}
