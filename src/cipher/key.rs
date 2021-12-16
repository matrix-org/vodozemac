use aes::{cipher::generic_array::GenericArray, Aes256, NewBlockCipher};
use block_modes::{block_padding::Pkcs7, BlockMode};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::Aes256Cbc;

type Aes256Key = GenericArray<u8, <Aes256 as NewBlockCipher>::KeySize>;
type Aes256Iv = GenericArray<u8, <Aes256Cbc as BlockMode<Aes256, Pkcs7>>::IvSize>;
type HmacSha256Key = [u8; 32];

#[derive(Zeroize)]
struct ExpandedKeys([u8; 80]);

impl Drop for ExpandedKeys {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ExpandedKeys {
    const OLM_HKDF_INFO: &'static [u8] = b"OLM_KEYS";
    const MEGOLM_HKDF_INFO: &'static [u8] = b"MEGOLM_KEYS";

    fn new(message_key: &[u8; 32]) -> Self {
        Self::new_helper(message_key, Self::OLM_HKDF_INFO)
    }

    fn new_megolm(message_key: &[u8; 128]) -> Self {
        Self::new_helper(message_key, Self::MEGOLM_HKDF_INFO)
    }

    fn new_helper(message_key: &[u8], info: &[u8]) -> Self {
        let mut expanded_keys = [0u8; 80];

        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), message_key);

        hkdf.expand(info, &mut expanded_keys).expect("Can't expand message key");

        Self(expanded_keys)
    }

    fn split(self) -> ([u8; 32], [u8; 16], [u8; 32]) {
        let mut aes_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        let mut aes_iv = [0u8; 16];

        aes_key.copy_from_slice(&self.0[0..32]);
        mac_key.copy_from_slice(&self.0[32..64]);
        aes_iv.copy_from_slice(&self.0[64..80]);

        (aes_key, aes_iv, mac_key)
    }
}

#[derive(Zeroize)]
pub(super) struct CipherKeys {
    aes_key: [u8; 32],
    aes_iv: [u8; 16],
    mac_key: [u8; 32],
}

impl Drop for CipherKeys {
    fn drop(&mut self) {
        self.aes_key.zeroize();
        self.aes_iv.zeroize();
        self.mac_key.zeroize();
    }
}

impl CipherKeys {
    pub fn new(message_key: &[u8; 32]) -> Self {
        let expanded_keys = ExpandedKeys::new(message_key);

        Self::new_helper(expanded_keys)
    }

    pub fn new_megolm(message_key: &[u8; 128]) -> Self {
        let expanded_keys = ExpandedKeys::new_megolm(message_key);

        Self::new_helper(expanded_keys)
    }

    fn new_helper(expanded_keys: ExpandedKeys) -> Self {
        let (aes_key, aes_iv, mac_key) = expanded_keys.split();

        Self { aes_key, aes_iv, mac_key }
    }

    pub fn aes_key(&self) -> &Aes256Key {
        Aes256Key::from_slice(&self.aes_key)
    }

    pub fn mac_key(&self) -> &HmacSha256Key {
        &self.mac_key
    }

    pub fn iv(&self) -> &Aes256Iv {
        Aes256Iv::from_slice(&self.aes_iv)
    }
}
