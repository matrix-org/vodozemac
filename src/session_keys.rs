use serde::{Deserialize, Serialize};

use crate::Curve25519PublicKey;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SessionKeys {
    pub(crate) identity_key: Curve25519PublicKey,
    pub(crate) base_key: Curve25519PublicKey,
    pub(crate) one_time_key: Curve25519PublicKey,
}

impl SessionKeys {
    pub fn new(
        identity_key: Curve25519PublicKey,
        base_key: Curve25519PublicKey,
        one_time_key: Curve25519PublicKey,
    ) -> Self {
        Self { identity_key, base_key, one_time_key }
    }
}

pub(crate) type SessionKeysPickle = SessionKeys;
