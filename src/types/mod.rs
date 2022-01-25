// Copyright 2021 Denis Kasak, Damir Jelić
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

mod curve25519;
mod ed25519;

pub use curve25519::{Curve25519KeyError, Curve25519PublicKey};
pub(crate) use curve25519::{Curve25519Keypair, Curve25519KeypairPickle, Curve25519SecretKey};
pub(crate) use ed25519::{
    Ed25519Keypair, Ed25519KeypairPickle, Ed25519KeypairUnpicklingError, Ed25519Signature,
};
pub use ed25519::{Ed25519PublicKey, SignatureError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyId(pub(super) u64);

impl From<KeyId> for String {
    fn from(value: KeyId) -> String {
        value.to_base64()
    }
}

impl KeyId {
    pub fn to_base64(self) -> String {
        crate::utilities::base64_encode(self.0.to_be_bytes())
    }
}
