use rand::thread_rng;
use x25519_dalek::{
    PublicKey as Curve25519PublicKey, SharedSecret, StaticSecret as Curve25519SecretKey,
};

use super::{
    chain_key::RemoteChainKey,
    root_key::{RemoteRootKey, RootKey},
};

pub(super) struct RatchetKey(Curve25519SecretKey);

#[derive(Debug, PartialEq)]
pub(super) struct RatchetPublicKey(Curve25519PublicKey);

#[derive(Clone, Debug, Hash, PartialEq)]
pub struct RemoteRatchetKey(Curve25519PublicKey);

impl RatchetKey {
    pub fn new() -> Self {
        let rng = thread_rng();
        Self(Curve25519SecretKey::new(rng))
    }

    pub fn diffie_hellman(&self, other: &RemoteRatchetKey) -> SharedSecret {
        self.0.diffie_hellman(&other.0)
    }
}

impl RatchetPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl From<[u8; 32]> for RatchetPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        RatchetPublicKey(Curve25519PublicKey::from(bytes))
    }
}

impl From<[u8; 32]> for RemoteRatchetKey {
    fn from(bytes: [u8; 32]) -> Self {
        RemoteRatchetKey(Curve25519PublicKey::from(bytes))
    }
}

impl From<Curve25519PublicKey> for RemoteRatchetKey {
    fn from(key: Curve25519PublicKey) -> Self {
        RemoteRatchetKey(key)
    }
}

impl AsRef<Curve25519PublicKey> for RatchetPublicKey {
    fn as_ref(&self) -> &Curve25519PublicKey {
        &self.0
    }
}

impl From<&RatchetKey> for RatchetPublicKey {
    fn from(r: &RatchetKey) -> Self {
        RatchetPublicKey(Curve25519PublicKey::from(&r.0))
    }
}

pub(super) struct Ratchet {
    root_key: RootKey,
    ratchet_key: RatchetKey,
}

impl Ratchet {
    pub fn new(root_key: RootKey) -> Self {
        let ratchet_key = RatchetKey::new();

        Self { root_key, ratchet_key }
    }

    pub fn new_with_ratchet_key(root_key: RootKey, ratchet_key: RatchetKey) -> Self {
        Self { root_key, ratchet_key }
    }

    pub fn advance(
        &self,
        remote_key: RemoteRatchetKey,
    ) -> (RemoteRootKey, RemoteRatchet, RemoteChainKey) {
        let (remote_root_key, remote_chain_key) =
            self.root_key.advance(&self.ratchet_key, &remote_key);

        let remote_ratchet = RemoteRatchet(remote_key);

        (remote_root_key, remote_ratchet, remote_chain_key)
    }

    pub fn ratchet_key(&self) -> &RatchetKey {
        &self.ratchet_key
    }
}

#[derive(Clone, Debug, Hash)]
pub(super) struct RemoteRatchet(RemoteRatchetKey);

impl RemoteRatchet {
    pub fn new(remote_ratchet_key: RemoteRatchetKey) -> Self {
        Self(remote_ratchet_key)
    }

    pub fn belongs_to(&self, remote_key: &RemoteRatchetKey) -> bool {
        &self.0 == remote_key
    }
}
