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

#![allow(dead_code)]

use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};
use hmac::{Hmac, Mac as _};
use prost::Message;
use rand::{thread_rng, RngCore};
use sha2::{digest::CtOutput, Sha256};
use zeroize::Zeroize;

use crate::cipher::{Cipher, Mac};
use crate::messages::Encode;
use crate::utilities::base64_encode;

const ADVANCEMENT_SEEDS: [&[u8; 1]; 4] = [b"\x00", b"\x01", b"\x02", b"\x03"];
const SESSION_KEY_VERSION: u8 = 2;

struct MegolmMessage(Vec<u8>);

impl MegolmMessage {
    pub fn new(ciphertext: Vec<u8>, message_index: u32) -> Self {
        let message = InnerMegolmMessage { message_index: message_index.into(), ciphertext };

        Self(message.encode_manual())
    }

    fn mac_start(&self) -> usize {
        self.0.len() - (Mac::TRUNCATED_LEN + ed25519_dalek::SIGNATURE_LENGTH)
    }

    pub fn bytes_for_mac(&self) -> &[u8] {
        &self.0[..self.mac_start()]
    }

    pub fn append_mac(&mut self, mac: Mac) {
        let mac = mac.truncate();
        let mac_start = self.mac_start();

        self.0[mac_start..mac_start + mac.len()].copy_from_slice(&mac);
    }

    fn signature_start(&self) -> usize {
        self.0.len() - ed25519_dalek::SIGNATURE_LENGTH
    }

    pub fn bytes_for_signing(&self) -> &[u8] {
        &self.0[..self.signature_start()]
    }

    pub fn append_signature(&mut self, signature: ed25519_dalek::Signature) {
        let signature_start = self.signature_start();
        self.0[signature_start..].copy_from_slice(&signature.to_bytes());
    }
}

impl AsRef<[u8]> for MegolmMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Message, PartialEq)]
struct InnerMegolmMessage {
    #[prost(uint64, tag = "8")]
    pub message_index: u64,
    #[prost(bytes, tag = "12")]
    pub ciphertext: Vec<u8>,
}

impl InnerMegolmMessage {
    const VERSION: u8 = 3;

    const INDEX_TAG: &'static [u8; 1] = b"\x08";
    const CIPHER_TAG: &'static [u8; 1] = b"\x12";

    fn encode_manual(&self) -> Vec<u8> {
        // Prost optimizes away the chain index if it's 0, libolm can't decode
        // this, so encode our messages the pedestrian way instead.
        let index = self.message_index.encode();
        let ciphertext_len = self.ciphertext.len().encode();

        [
            [Self::VERSION].as_ref(),
            Self::INDEX_TAG.as_ref(),
            &index,
            Self::CIPHER_TAG.as_ref(),
            &ciphertext_len,
            &self.ciphertext,
            &[0u8; Mac::TRUNCATED_LEN],
            &[0u8; ed25519_dalek::SIGNATURE_LENGTH],
        ]
        .concat()
    }
}

pub struct GroupSession {
    ratchet: Ratchet,
    signing_key: ExpandedSecretKey,
    public_key: PublicKey,
}

impl GroupSession {
    pub fn new() -> Self {
        let mut rng = thread_rng();

        let secret_key = SecretKey::generate(&mut rng);
        let secret_key = ExpandedSecretKey::from(&secret_key);
        let public_key = PublicKey::from(&secret_key);

        Self { signing_key: secret_key, public_key, ratchet: Ratchet::new() }
    }

    pub fn session_id(&self) -> String {
        base64_encode(self.public_key.as_bytes())
    }

    pub fn message_index(&self) -> u32 {
        self.ratchet.index()
    }

    pub fn encrypt(&mut self, plaintext: &str) -> String {
        let cipher = Cipher::new_megolm(self.ratchet.as_bytes());

        let ciphertext = cipher.encrypt(plaintext.as_ref());
        let mut message = MegolmMessage::new(ciphertext, self.message_index());

        let mac = cipher.mac(message.bytes_for_mac());
        message.append_mac(mac);

        let signature = self.signing_key.sign(message.bytes_for_signing(), &self.public_key);
        message.append_signature(signature);

        self.ratchet.advance();

        base64_encode(message)
    }

    pub fn session_key(&self) -> String {
        let index = self.ratchet.index().to_le_bytes();

        let mut export: Vec<u8> = [
            [SESSION_KEY_VERSION].as_ref(),
            index.as_ref(),
            self.ratchet.as_bytes(),
            self.public_key.as_bytes(),
        ]
        .concat();

        let signature = self.signing_key.sign(&export, &self.public_key);
        export.extend(signature.to_bytes());

        let result = base64_encode(&export);
        export.zeroize();

        result
    }
}

pub struct InboundGroupSession {
    initial_ratchet: Ratchet,
    latest_ratchet: Ratchet,
    signing_key: PublicKey,
}

#[derive(Zeroize, Clone)]
struct Ratchet {
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

    fn new() -> Self {
        let mut rng = thread_rng();

        let mut ratchet = Self { inner: [0u8; 128], counter: 0 };

        rng.fill_bytes(&mut ratchet.inner);

        ratchet
    }

    fn index(&self) -> u32 {
        self.counter
    }

    fn as_bytes(&self) -> &[u8; 128] {
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

    fn advance(&mut self) {
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

    fn advance_to(&mut self, _index: u32) {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use olm_rs::inbound_group_session::OlmInboundGroupSession;

    use super::GroupSession;

    #[test]
    fn encrypting() -> Result<()> {
        let mut session = GroupSession::new();
        let session_key = session.session_key();

        let olm_session = OlmInboundGroupSession::new(&session_key)?;

        let plaintext = "It's a secret to everybody";
        let message = session.encrypt(plaintext);

        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        let plaintext = "Another secret";
        let message = session.encrypt(plaintext);

        let (decrypted, _) = olm_session.decrypt(message)?;
        assert_eq!(decrypted, plaintext);

        let plaintext = "And another secret";
        let message = session.encrypt(plaintext);
        let (decrypted, _) = olm_session.decrypt(message)?;

        assert_eq!(decrypted, plaintext);

        Ok(())
    }
}
