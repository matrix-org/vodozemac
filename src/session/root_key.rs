use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    ratchet::{RatchetKey, RemoteRatchetKey},
};

const ADVANCEMENT_SEED: &[u8; 11] = b"OLM_RATCHET";

#[derive(Zeroize)]
pub(crate) struct RootKey {
    pub key: [u8; 32],
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[derive(Zeroize)]
pub(crate) struct RemoteRootKey {
    pub key: [u8; 32],
}

impl Drop for RemoteRootKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

fn diffie_hellman(
    root_key: &[u8; 32],
    ratchet_key: &RatchetKey,
    remote_ratchet_key: &RemoteRatchetKey,
) -> [u8; 64] {
    let shared_secret = ratchet_key.diffie_hellman(remote_ratchet_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(root_key.as_ref()), shared_secret.as_bytes());
    let mut output = [0u8; 64];

    hkdf.expand(ADVANCEMENT_SEED, &mut output).expect("Can't expand");

    output
}

impl RemoteRootKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    pub(super) fn advance(
        &self,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RootKey, ChainKey, RatchetKey) {
        let ratchet_key = RatchetKey::new();
        let output = diffie_hellman(&self.key, &ratchet_key, remote_ratchet_key);

        let mut chain_key = [0u8; 32];
        let mut root_key = [0u8; 32];

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        let chain_key = ChainKey::new(chain_key);
        let root_key = RootKey::new(root_key);

        (root_key, chain_key, ratchet_key)
    }
}

impl RootKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    pub(super) fn advance(
        &self,
        old_ratchet_key: &RatchetKey,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RemoteRootKey, RemoteChainKey) {
        let output = diffie_hellman(&self.key, old_ratchet_key, remote_ratchet_key);

        let mut chain_key = [0u8; 32];
        let mut root_key = [0u8; 32];

        root_key.copy_from_slice(&output[..32]);
        chain_key.copy_from_slice(&output[32..]);

        let root_key = RemoteRootKey::new(root_key);
        let chain_key = RemoteChainKey::new(chain_key);

        (root_key, chain_key)
    }
}
