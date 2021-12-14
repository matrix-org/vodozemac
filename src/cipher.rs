use aes::{cipher::generic_array::GenericArray, Aes256, NewBlockCipher};
use block_modes::{block_padding::Pkcs7, BlockMode, BlockModeError, Cbc};
use hkdf::Hkdf;
use hmac::{digest::MacError, Hmac, Mac as MacT};
use sha2::Sha256;
use zeroize::Zeroize;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

type Aes256Key = GenericArray<u8, <Aes256 as NewBlockCipher>::KeySize>;
type Aes256Iv = GenericArray<u8, <Aes256Cbc as BlockMode<Aes256, Pkcs7>>::IvSize>;
type HmacSha256Key = [u8; 32];

#[derive(Clone, Zeroize)]
struct ExpandedKeys([u8; 80]);

impl Drop for ExpandedKeys {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ExpandedKeys {
    const HMAC_INFO: &'static [u8] = b"OLM_KEYS";

    fn new(message_key: &[u8; 32]) -> Self {
        let mut expanded_keys = [0u8; 80];

        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), message_key);

        hkdf.expand(Self::HMAC_INFO, &mut expanded_keys).expect("Can't expand message key");

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

pub(crate) struct Mac([u8; 32]);

impl Mac {
    pub const TRUNCATED_LEN: usize = 8;

    pub fn truncate(&self) -> [u8; Self::TRUNCATED_LEN] {
        let mut truncated = [0u8; Self::TRUNCATED_LEN];
        truncated.copy_from_slice(&self.0[0..Self::TRUNCATED_LEN]);

        truncated
    }
}

#[derive(Clone, Zeroize)]
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
        let expanded_key = ExpandedKeys::new(message_key);
        let (aes_key, aes_iv, mac_key) = expanded_key.split();

        Self { aes_key, aes_iv, mac_key }
    }

    fn aes_key(&self) -> &Aes256Key {
        Aes256Key::from_slice(&self.aes_key)
    }

    fn mac_key(&self) -> &HmacSha256Key {
        &self.mac_key
    }

    fn iv(&self) -> &Aes256Iv {
        Aes256Iv::from_slice(&self.aes_iv)
    }
}

pub(super) struct Cipher {
    keys: CipherKeys,
}

impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let keys = CipherKeys::new(key);

        Self { keys }
    }

    fn get_cipher(&self) -> Aes256Cbc {
        Aes256Cbc::new_fix(self.keys.aes_key(), self.keys.iv())
    }

    fn get_hmac(&self) -> HmacSha256 {
        // We don't use HmacSha256::new() here because new() expects a 64 byte
        // large Hmac key, the Olm spec defines a 32 byte long one instead.
        //
        // https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md#version-1
        HmacSha256::new_from_slice(self.keys.mac_key()).expect("Invalid HMAC key size")
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.get_cipher();
        cipher.encrypt_vec(plaintext)
    }

    pub fn mac(&self, message: &[u8]) -> Mac {
        let mut hmac = self.get_hmac();
        hmac.update(message);

        let mac_bytes = hmac.finalize().into_bytes();

        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_bytes);

        Mac(mac)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BlockModeError> {
        let cipher = self.get_cipher();
        cipher.decrypt_vec(ciphertext)
    }

    pub fn verify_mac(&self, message: &[u8], tag: &[u8]) -> Result<(), MacError> {
        let mut hmac = self.get_hmac();

        hmac.update(message);
        hmac.verify_truncated_left(tag)
    }
}
