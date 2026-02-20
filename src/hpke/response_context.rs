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

//! Support for bidirectional communication in a HPKE channel.
//!
//! The scheme implemented here is described in the oblivous HTTP RFC in
//! [section 4.4]. The one difference from the oblivious HTTP RFC is that we
//! construct a HPKE context from the key and nonce we derive using the oblivous
//! HTTP scheme instead of directly encrypting a message.
//!
//! [section 4.4]: https://www.rfc-editor.org/rfc/rfc9458#name-encapsulation-of-responses

use hkdf::Hkdf;
use hpke::{
    HpkeError,
    aead::{AeadCtxR, AeadCtxS, AeadKey, AeadNonce},
    streaming_enc::{ExporterSecret, create_receiver_context, create_sender_context},
};
use sha2::Sha256;
use zeroize::Zeroize;

use super::{Aead, Kdf, Kem};
use crate::Curve25519PublicKey;

pub(super) trait CreateResponseContext {
    type ResponseContext;

    fn export(&self, info: &[u8], output: &mut [u8]) -> Result<(), HpkeError>;

    fn create_context(
        &self,
        response_key: &AeadKey<Aead>,
        response_nonce: AeadNonce<Aead>,
    ) -> Self::ResponseContext;

    fn create_response_context(
        &self,
        application_info_prefix: &str,
        encapsulated_key: Curve25519PublicKey,
        response_nonce: &[u8],
    ) -> Self::ResponseContext {
        let mut secret = [0u8; 32];

        // Export a secret from the HPKE context, we use our application info prefix and
        // append "_RESPONSE" to it.
        let info = format!("{application_info_prefix}_RESPONSE");

        #[allow(clippy::expect_used)]
        self.export(info.as_bytes(), &mut secret)
            .expect("We should be able to export 32 bytes from the HPKE export interface");

        // For the salt we concatenate the public key of the sender and the randomly
        // generated response nonce.
        let salt: Vec<u8> = [encapsulated_key.as_bytes().as_slice(), response_nonce].concat();

        // Now create a KDF from the salt and the previously secret exported from the
        // HPKE context.
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &secret);

        // From the KDF expand an AEAD key and nonce.
        let mut aead_key = AeadKey::default();
        let mut aead_nonce = AeadNonce::default();

        #[allow(clippy::expect_used)]
        hkdf.expand(b"key", aead_key.0.as_mut_slice())
            .expect("We should be able to expand the base response secret into a AEAD key");

        #[allow(clippy::expect_used)]
        hkdf.expand(b"nonce", aead_nonce.0.as_mut_slice())
            .expect("We should be able to expand the base response secret into a response nonce");

        // Check that our key and nonce aren't just zeroes, this is only checked in
        // debug builds.
        debug_assert_ne!(aead_nonce.0.as_slice(), [0u8; 12]);
        debug_assert_ne!(aead_key.0.as_slice(), [0u8; 32]);

        // Let's get rid of the secret.
        secret.zeroize();

        // Now create a HPKE context which can be used to communicate in the other
        // direction.
        self.create_context(&aead_key, aead_nonce)
    }
}

impl CreateResponseContext for AeadCtxS<Aead, Kdf, Kem> {
    type ResponseContext = AeadCtxR<Aead, Kdf, Kem>;

    fn export(&self, info: &[u8], output: &mut [u8]) -> Result<(), HpkeError> {
        self.export(info, output)
    }

    fn create_context(
        &self,
        response_key: &AeadKey<Aead>,
        response_nonce: AeadNonce<Aead>,
    ) -> Self::ResponseContext {
        // We create an default, all zeroes exporter secret as the HPKE
        // `create_ROLE_context()` methods require it, but we never use the
        // export interface of this HPKE context.
        let exporter_secret = ExporterSecret::default();
        create_receiver_context(response_key, response_nonce, exporter_secret)
    }
}

impl CreateResponseContext for AeadCtxR<Aead, Kdf, Kem> {
    type ResponseContext = AeadCtxS<Aead, Kdf, Kem>;

    fn export(&self, info: &[u8], output: &mut [u8]) -> Result<(), HpkeError> {
        self.export(info, output)
    }

    fn create_context(
        &self,
        response_key: &AeadKey<Aead>,
        response_nonce: AeadNonce<Aead>,
    ) -> Self::ResponseContext {
        // We create an default, all zeroes exporter secret as the HPKE
        // `create_ROLE_context()` methods require it, but we never use the
        // export interface of this HPKE context.
        let exporter_secret = ExporterSecret::default();
        create_sender_context(response_key, response_nonce, exporter_secret)
    }
}
