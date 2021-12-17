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
use rand::{thread_rng, RngCore};
use sha2::{digest::CtOutput, Sha256};
use zeroize::Zeroize;

const ADVANCEMENT_SEEDS: [&[u8; 1]; 4] = [b"\x00", b"\x01", b"\x02", b"\x03"];

#[derive(Zeroize, Clone)]
pub(super) struct Ratchet {
    inner: [u8; 128],
    counter: u32,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.inner.zeroize();
        self.counter.zeroize();
    }
}

struct RatchetPart<'a> {
    part: &'a mut [u8],
    advancement_seed: &'static [u8; 1],
}

impl<'a> RatchetPart<'a> {
    fn r_0(part: &'a mut [u8]) -> Self {
        Self { part, advancement_seed: ADVANCEMENT_SEEDS[0] }
    }

    fn r_1(part: &'a mut [u8]) -> Self {
        Self { part, advancement_seed: ADVANCEMENT_SEEDS[1] }
    }

    fn r_2(part: &'a mut [u8]) -> Self {
        Self { part, advancement_seed: ADVANCEMENT_SEEDS[2] }
    }

    fn r_3(part: &'a mut [u8]) -> Self {
        Self { part, advancement_seed: ADVANCEMENT_SEEDS[3] }
    }

    fn hash(&self) -> CtOutput<Hmac<Sha256>> {
        let mut hmac =
            Hmac::<Sha256>::new_from_slice(self.part).expect("Can't create a HMAC object");
        hmac.update(self.advancement_seed);

        hmac.finalize()
    }

    fn update(&mut self, new_part: &[u8]) {
        self.part.copy_from_slice(new_part);
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
        let from = match from {
            0 => &self.r_0,
            1 => &self.r_1,
            2 => &self.r_2,
            3 => &self.r_3,
            _ => unreachable!(),
        };

        let result = from.hash();

        let to = match to {
            0 => &mut self.r_0,
            1 => &mut self.r_1,
            2 => &mut self.r_3,
            3 => &mut self.r_3,
            _ => unreachable!(),
        };

        to.update(&result.into_bytes());
    }
}

impl Ratchet {
    const RATCHET_PART_COUNT: usize = 4;

    pub fn new() -> Self {
        let mut rng = thread_rng();

        let mut ratchet = Self { inner: [0u8; 128], counter: 0 };

        rng.fill_bytes(&mut ratchet.inner);

        ratchet
    }

    pub fn index(&self) -> u32 {
        self.counter
    }

    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.inner
    }

    fn as_parts(&mut self) -> RatchetParts {
        let (top, bottom) = self.inner.split_at_mut(64);

        let (r_0, r_1) = top.split_at_mut(32);
        let (r_2, r_3) = bottom.split_at_mut(32);

        let r_0 = RatchetPart::r_0(r_0);
        let r_1 = RatchetPart::r_1(r_1);
        let r_2 = RatchetPart::r_2(r_2);
        let r_3 = RatchetPart::r_3(r_3);

        RatchetParts { r_0, r_1, r_2, r_3 }
    }

    pub fn advance(&mut self) {
        let mut mask: u32 = 0x00FFFFFF;
        let mut h = 0;

        self.counter += 1;

        // figure out how much we need to rekey
        while h < 4 {
            if (self.counter & mask) == 0 {
                break;
            }

            h += 1;
            mask >>= 8;
        }

        // now update R(h)...R(3) based on R(h)
        for i in Self::RATCHET_PART_COUNT - 1..h + 1 {
            let mut parts = self.as_parts();

            parts.update(h, i);
        }
    }

    pub fn advance_to(&mut self, _advance_to: u32) {
        todo!()
    }
}
