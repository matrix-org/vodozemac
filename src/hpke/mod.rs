// Copyright 2025 The Matrix.org Foundation C.I.C.
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

//! Implementation of an hybrid public encryption scheme.

#![allow(dead_code)]
#![allow(missing_docs)]

mod error;
mod messages;

use error::*;
use hpke::{
    Deserializable as _, OpModeS, Serializable,
    aead::{AeadCtxR, AeadCtxS, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
};
use messages::*;
use rand::rng;

use crate::{Curve25519PublicKey, Curve25519SecretKey};

const MATRIX_QR_LOGIN_INFO_PREFIX: &str = "MATRIX_QR_CODE_LOGIN";

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

type AeadSenderContext = AeadCtxS<Aead, Kdf, Kem>;
type AeadRecipientContext = AeadCtxR<Aead, Kdf, Kem>;

const TODO_REPLACE_INFO: &[u8] = b"REPLY_KEY";

#[derive(Debug)]
pub struct InboundCreationResult {
    /// The established HPKE channel.
    pub hpke: EstablishedHpkeChannel,
    /// The plaintext of the initial message.
    pub message: Vec<u8>,
}

#[derive(Debug)]
pub struct OutboundCreationResult {
    /// The established HPKE channel.
    pub hpke: EstablishedHpkeChannel,
    /// The initial message.
    pub message: InitialMessage,
}

#[derive(Debug)]
pub struct EstablishedHpkeChannel {}

pub struct HpkeRecipientChannel {
    secret_key: Curve25519SecretKey,
    application_info_prefix: String,
}

pub struct HpkeSenderChannel {
    application_info_prefix: String,
}

/// The possible device roles for an HPKE channel, indicating whether the
/// device is initiating the channel or receiving/responding as the other side
/// of the initiation.
#[derive(Debug, Clone, Copy)]
enum Role {
    Initiator,
    Recipient,
}

impl HpkeSenderChannel {
    /// Create a new, random, unestablished HPKE session.
    ///
    /// This method will use the `MATRIX_QR_CODE_LOGIN` info. If you are using
    /// this for a different purpose, consider using the
    /// [`HpkeSenderChannel::with_info()`] method.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_info(MATRIX_QR_LOGIN_INFO_PREFIX)
    }

    /// Create a new, random, unestablished HPKE session with the given
    /// application info.
    ///
    /// The application info will be used to derive the various secrets and
    /// provide domain separation.
    pub fn with_info(info: &str) -> Self {
        Self { application_info_prefix: info.to_owned() }
    }

    /// Create an [`EstablishedEcies`] session using the other side's Curve25519
    /// public key and an initial plaintext.
    ///
    /// After the channel has been established, we can encrypt messages to send
    /// to the other side. The other side uses the initial message to
    /// establishes the same channel on its side.
    pub fn establish_channel(
        self,
        their_public_key: Curve25519PublicKey,
        initial_plaintext: &[u8],
    ) -> Result<OutboundCreationResult, Error> {
        let mut rng = rng();

        let their_public_key =
            <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(their_public_key.as_bytes())
                .unwrap();

        let (encapsulated_key, mut context): (_, AeadSenderContext) = hpke::setup_sender(
            &OpModeS::Base,
            &their_public_key,
            self.application_info_prefix.as_bytes(),
            &mut rng,
        )
        .unwrap();

        let ciphertext = context.seal(initial_plaintext, &[]).unwrap();

        let mut decryption_key = Box::new([0u8; 32]);
        context.export(TODO_REPLACE_INFO, decryption_key.as_mut_slice()).unwrap();

        let encapsulated_key = encapsulated_key.to_bytes();
        let encapsulated_key =
            Curve25519PublicKey::from_slice(encapsulated_key.as_slice()).unwrap();

        Ok(OutboundCreationResult {
            hpke: EstablishedHpkeChannel {},
            message: InitialMessage { encapsulated_key, ciphertext },
        })
    }
}

impl HpkeRecipientChannel {
    /// Create a new, random, unestablished HPKE session.
    ///
    /// This method will use the `MATRIX_QR_CODE_LOGIN` info. If you are using
    /// this for a different purpose, consider using the
    /// [`HpkeRecipientChannel::with_info()`] method.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_info(MATRIX_QR_LOGIN_INFO_PREFIX)
    }

    /// Create a new, random, unestablished HPKE channel with the given
    /// application info.
    ///
    /// The application info will be used to derive the various secrets and
    /// provide domain separation.
    pub fn with_info(info: &str) -> Self {
        Self { secret_key: Curve25519SecretKey::new(), application_info_prefix: info.to_owned() }
    }

    /// Create a [`EstablishedEcies`] from an [`InitialMessage`] encrypted by
    /// the other side.
    pub fn establish_channel(
        self,
        message: &InitialMessage,
    ) -> Result<InboundCreationResult, Error> {
        let secret_key =
            <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(self.secret_key.as_bytes())
                .unwrap();

        let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
            message.encapsulated_key.as_bytes(),
        )
        .unwrap();

        let mut context: AeadRecipientContext = hpke::setup_receiver(
            &hpke::OpModeR::Base,
            &secret_key,
            &encapped_key,
            self.application_info_prefix.as_bytes(),
        )
        .unwrap();

        let message = context.open(&message.ciphertext, &[]).unwrap();

        let mut encryption_key = Box::new([0u8; 32]);
        context.export(TODO_REPLACE_INFO, encryption_key.as_mut_slice()).unwrap();

        Ok(InboundCreationResult { hpke: EstablishedHpkeChannel {}, message })
    }

    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side to be able to
    /// establish an HPKE channel.
    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(&self.secret_key)
    }
}
