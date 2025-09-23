// Copyright 2026 The Matrix.org Foundation C.I.C.
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

use cipher::{Array, consts::U32, crypto_common::Generate};
use hpke::{Deserializable as _, aead::AeadCtxR, kem::X25519HkdfSha256};

use crate::{
    Curve25519PublicKey, Curve25519SecretKey,
    hpke::{
        Aead, BidiereactionalCreationResult, CreateResponseContext, Error, EstablishedHpkeChannel,
        InitialMessage, InitialResponse, Kdf, Kem, MATRIX_QR_LOGIN_INFO_PREFIX, RecipientContext,
        Role, UnidirectionalHkpeChannel,
    },
};

/// The result type for the initial establishment of a unidirectional HPKE
/// channel.
#[derive(Debug)]
pub struct RecipientCreationResult {
    /// The established unidirectional HPKE recipient channel.
    pub channel: UnidirectionalRecipientChannel,
    /// The plaintext of the initial message.
    pub message: Vec<u8>,
}

/// The unestablished HPKE recipient channel.
pub struct HpkeRecipientChannel {
    /// The secret key which will be used to establish a shared secret between
    /// the recipient and sender.
    secret_key: Curve25519SecretKey,

    /// The application prefix which will be used as the info string to derive
    /// secrets.
    application_info_prefix: String,
}

impl std::fmt::Debug for HpkeRecipientChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let public_key = Curve25519PublicKey::from(&self.secret_key);

        f.debug_struct("HpkeRecipientChannel")
            .field("our_public_key", &public_key)
            .field("application_info_prefix", &self.application_info_prefix)
            .finish_non_exhaustive()
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

    /// Create a [`EstablishedHpkeChannel`] from an [`InitialMessage`] encrypted
    /// by the other side.
    pub fn establish_channel(
        self,
        message: &InitialMessage,
        aad: &[u8],
    ) -> Result<RecipientCreationResult, Error> {
        let Self { secret_key, application_info_prefix } = self;
        let InitialMessage { encapsulated_key, ciphertext } = message;

        let their_public_key = *encapsulated_key;
        let our_public_key = Curve25519PublicKey::from(&secret_key);

        let secret_key = convert_secret_key(&secret_key);
        let encapsulated_key = convert_encapsulated_key(encapsulated_key);

        let mut context: RecipientContext = hpke::setup_receiver(
            &hpke::OpModeR::Base,
            &secret_key,
            &encapsulated_key,
            application_info_prefix.as_bytes(),
        )
        .map_err(|_| Error::Decryption)?;

        let message = context.open(ciphertext, aad).map_err(|_| Error::Decryption)?;

        let channel = UnidirectionalRecipientChannel(UnidirectionalHkpeChannel {
            application_info_prefix,
            context,
            their_public_key,
            our_public_key,
        });

        Ok(RecipientCreationResult { channel, message })
    }

    /// Get our [`Curve25519PublicKey`].
    ///
    /// This public key needs to be sent to the other side to be able to
    /// establish an HPKE channel.
    pub fn public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from(&self.secret_key)
    }
}

// Convert our Curve25519 secret key type into the PrivateKey type the HPKE
// crate expects.
//
// Underneath those types are the same but we are forced to go through the byte
// interface due to the HPKE crate not exposing methods to do direct
// conversions.
fn convert_secret_key(
    secret_key: &Curve25519SecretKey,
) -> <X25519HkdfSha256 as hpke::Kem>::PrivateKey {
    #[allow(clippy::expect_used)]
    <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(secret_key.as_bytes()).expect(
        "Converting from our PrivateKey type to the HPKE private key type should never fail",
    )
}

/// Same as [`convert_secret_key()`] just for the encapsulated key.
fn convert_encapsulated_key(
    public_key: &Curve25519PublicKey,
) -> <X25519HkdfSha256 as hpke::Kem>::EncappedKey {
    #[allow(clippy::expect_used)]
    <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(public_key.as_bytes())
        .expect("Converting to the HPKE EncappedKey type should never fail")
}

/// The unidirectional HPKE sender channel.
///
/// This channel is created when we open the initial message. It allows us to
/// seal the initial response at which point the channel gets transformed into a
/// fully established and bidirectional HPKE channel.
pub struct UnidirectionalRecipientChannel(UnidirectionalHkpeChannel<AeadCtxR<Aead, Kdf, Kem>>);

impl std::fmt::Debug for UnidirectionalRecipientChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnidirectionalRecipientChannel")
            .field("application_info_prefix", &self.0.application_info_prefix)
            .field("their_public_key", &self.0.their_public_key)
            .field("our_public_key", &self.0.our_public_key)
            .finish_non_exhaustive()
    }
}

impl UnidirectionalRecipientChannel {
    /// Seal the given plaintext using the associated data and this
    /// [`UnidirectionalRecipientChannel`].
    ///
    /// This method will encrypt the given plaintext for the other side of this
    /// channel and fully establish the HPKE channel, enabling bidirectional
    /// communication.
    ///
    /// # Panics
    ///
    /// If the additional associated data is too big, it has to be shorter than
    /// 2^64 bytes.
    pub fn establish_bidirectional_channel(
        self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> BidiereactionalCreationResult<InitialResponse> {
        let Self(UnidirectionalHkpeChannel {
            context,
            their_public_key,
            our_public_key,
            application_info_prefix,
        }) = self;

        let base_response_nonce = Array::<u8, U32>::generate();

        let mut response_context = context.create_response_context(
            &application_info_prefix,
            their_public_key,
            &base_response_nonce,
        );

        #[allow(clippy::expect_used)]
        let ciphertext = response_context
            .seal(plaintext, aad)
            .expect("We should be able to seal the initial response");

        let role = Role::Recipient { context, response_context };
        let check_code =
            role.check_code(&application_info_prefix, our_public_key, their_public_key);

        let channel = EstablishedHpkeChannel { our_public_key, their_public_key, role, check_code };

        BidiereactionalCreationResult {
            channel,
            message: InitialResponse {
                ciphertext,
                base_response_nonce: base_response_nonce.to_vec(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;

    use super::*;
    use crate::hpke::{HpkeSenderChannel, SenderCreationResult};

    #[test]
    fn snapshot_debug() {
        let key = Curve25519SecretKey::from_slice(&[0; 32]);
        let mut bob = HpkeRecipientChannel::new();
        bob.secret_key = key;

        assert_debug_snapshot!(bob);
    }

    #[test]
    fn snapshot_debug_unidirectional_channel() {
        let key = Curve25519SecretKey::from_slice(&[0; 32]);

        let alice = HpkeSenderChannel::new();
        let mut bob = HpkeRecipientChannel::new();
        bob.secret_key = key;

        assert_debug_snapshot!(bob);

        let SenderCreationResult { message, .. } =
            alice.establish_channel(bob.public_key(), b"", &[]);

        let RecipientCreationResult { channel: mut bob, .. } =
            bob.establish_channel(&message, &[]).unwrap();

        let key = Curve25519PublicKey::from_bytes([0; 32]);

        bob.0.our_public_key = key;
        bob.0.their_public_key = key;

        assert_debug_snapshot!(bob);
    }
}
