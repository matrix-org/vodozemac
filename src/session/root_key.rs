use hkdf::Hkdf;
use sha2::Sha256;

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    ratchet::{RatchetKey, RemoteRatchetKey},
};

const ADVANCEMENT_SEED: &[u8; 11] = b"OLM_RATCHET";

pub(super) struct RootKey([u8; 32]);
pub(super) struct RemoteRootKey {
    key: [u8; 32],
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

    pub fn advance(self, remote_ratchet_key: &RemoteRatchetKey) -> (RootKey, ChainKey, RatchetKey) {
        let ratchet_key = RatchetKey::new();
        let output = diffie_hellman(&self.key, &ratchet_key, remote_ratchet_key);

        let mut chain_key = ChainKey::new([0u8; 32]);
        let mut root_key = RootKey([0u8; 32]);

        root_key.0.copy_from_slice(&output[..32]);
        chain_key.fill(&output[32..]);

        (root_key, chain_key, ratchet_key)
    }
}

impl RootKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn advance(
        &self,
        old_ratchet_key: &RatchetKey,
        remote_ratchet_key: &RemoteRatchetKey,
    ) -> (RemoteRootKey, RemoteChainKey) {
        let output = diffie_hellman(&self.0, old_ratchet_key, remote_ratchet_key);

        let mut chain_key = RemoteChainKey::new([0u8; 32]);
        let mut root_key = RemoteRootKey { key: [0u8; 32] };

        root_key.key.copy_from_slice(&output[..32]);
        chain_key.fill(&output[32..]);

        (root_key, chain_key)
    }
}
