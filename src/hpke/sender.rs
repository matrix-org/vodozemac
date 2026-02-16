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

use hpke::{
    Deserializable as _, OpModeS, Serializable as _, aead::AeadCtxS, kem::X25519HkdfSha256,
};
use rand::rng;

use crate::{
    Curve25519PublicKey,
    hpke::{
        Aead, BidirectionalCreationResult, CreateResponseContext, Error, EstablishedHpkeChannel,
        InitialMessage, InitialResponse, Kdf, Kem, MATRIX_QR_LOGIN_INFO_PREFIX, Role,
        UnidirectionalHkpeChannel,
    },
};

/// The result type for the initial establishment of a unidirectional HPKE
/// channel.
pub struct SenderCreationResult {
    /// The established unidirectional HPKE sender channel.
    pub channel: UnidirectionalSenderChannel,
    /// The initial message.
    pub message: InitialMessage,
}

/// The unestablished HPKE sender channel.
#[derive(Debug)]
pub struct HpkeSenderChannel {
    /// The application prefix which will be used as the info string to derive
    /// secrets.
    application_info_prefix: String,
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

    /// Create an [`EstablishedHpkeChannel`] session using the other side's
    /// Curve25519 public key and an initial plaintext.
    ///
    /// After the channel has been established, we can encrypt messages to send
    /// to the other side. The other side uses the initial message to
    /// establishes the same channel on its side.
    pub fn establish_channel(
        self,
        their_public_key: Curve25519PublicKey,
        initial_plaintext: &[u8],
        aad: &[u8],
    ) -> SenderCreationResult {
        let Self { application_info_prefix } = self;

        let mut rng = rng();
        let their_key = convert_public_key(their_public_key);

        #[allow(clippy::expect_used)]
        let (encapsulated_key, mut context) = hpke::setup_sender(
            &OpModeS::Base,
            &their_key,
            application_info_prefix.as_bytes(),
            &mut rng,
        )
        .expect("Encapsulating an X25519 public key never fails since the encapsulation is just the bytes of the public key");

        #[allow(clippy::expect_used)]
        let ciphertext = context
            .seal(initial_plaintext, aad)
            .expect("We should be able to seal the initial plaintext");

        let encapsulated_key = convert_encapsulated_key(encapsulated_key);
        let our_public_key = encapsulated_key;

        let channel = UnidirectionalSenderChannel(UnidirectionalHkpeChannel {
            context,
            application_info_prefix,
            our_public_key,
            their_public_key,
        });

        SenderCreationResult { channel, message: InitialMessage { encapsulated_key, ciphertext } }
    }
}

/// Convert our Curve25519 public key type into the type the HPKE crate expects.
fn convert_public_key(
    public_key: Curve25519PublicKey,
) -> <X25519HkdfSha256 as hpke::Kem>::PublicKey {
    #[allow(clippy::expect_used)]
    <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key.as_bytes())
        .expect("Converting the Dalek public key to the HPKE public key should always work")
}

/// Convert a EncappedKey from the HPKE crate to our own Curve25519 public key
/// type.
fn convert_encapsulated_key(
    encapsulated_key: <X25519HkdfSha256 as hpke::Kem>::EncappedKey,
) -> Curve25519PublicKey {
    let encapsulated_key = encapsulated_key.to_bytes();
    #[allow(clippy::expect_used)]
    Curve25519PublicKey::from_slice(encapsulated_key.as_slice())
        .expect("Converting from the HPKE public key to the Dalek public key should always work")
}

/// The unidirectional HPKE sender channel.
///
/// This channel is created when we seal the initial plaintext and we wait for
/// the initial response. from the other side.
pub struct UnidirectionalSenderChannel(UnidirectionalHkpeChannel<AeadCtxS<Aead, Kdf, Kem>>);

impl std::fmt::Debug for UnidirectionalSenderChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnidirectionalSenderChannel")
            .field("application_info_prefix", &self.0.application_info_prefix)
            .field("our_public_key", &self.0.our_public_key)
            .field("their_public_key", &self.0.their_public_key)
            .finish_non_exhaustive()
    }
}

impl UnidirectionalSenderChannel {
    /// Open the initial response using the associated data and this
    /// [`UnidirectionalSenderChannel`].
    ///
    /// This method will decrypt the given message coming from the other side of
    /// this channel and fully establish the HPKE channel, enabling
    /// bidirectional communication.
    pub fn establish_bidirectional_channel(
        self,
        message: &InitialResponse,
        aad: &[u8],
    ) -> Result<BidirectionalCreationResult<Vec<u8>>, Error> {
        let Self(UnidirectionalHkpeChannel {
            context,
            application_info_prefix,
            our_public_key,
            their_public_key,
        }) = self;

        let mut response_context = context.create_response_context(
            &application_info_prefix,
            our_public_key,
            &message.base_response_nonce,
        );

        let plaintext =
            response_context.open(&message.ciphertext, aad).map_err(|_| Error::Decryption)?;

        let role = Role::Sender { context, response_context };
        let check_code =
            role.check_code(&application_info_prefix, our_public_key, their_public_key);

        Ok(BidirectionalCreationResult {
            channel: EstablishedHpkeChannel { our_public_key, their_public_key, role, check_code },
            message: plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;

    use super::*;
    use crate::hpke::HpkeRecipientChannel;

    #[test]
    fn snapshot_debug() {
        let alice = HpkeSenderChannel::new();

        assert_debug_snapshot!(alice);
    }

    #[test]
    fn snapshot_debug_unidirectional_channel() {
        let key = Curve25519PublicKey::from_bytes([0; 32]);

        let alice = HpkeSenderChannel::new();
        let bob = HpkeRecipientChannel::new();

        let SenderCreationResult { channel: mut alice, .. } =
            alice.establish_channel(bob.public_key(), b"", &[]);

        alice.0.our_public_key = key;
        alice.0.their_public_key = key;

        assert_debug_snapshot!(alice);
    }
}
