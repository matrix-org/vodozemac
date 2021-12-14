mod key;

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, BlockModeError, Cbc};
use hmac::{digest::MacError, Hmac, Mac as MacT};
use key::CipherKeys;
use sha2::Sha256;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

pub(crate) struct Mac([u8; 32]);

impl Mac {
    pub const TRUNCATED_LEN: usize = 8;

    pub fn truncate(&self) -> [u8; Self::TRUNCATED_LEN] {
        let mut truncated = [0u8; Self::TRUNCATED_LEN];
        truncated.copy_from_slice(&self.0[0..Self::TRUNCATED_LEN]);

        truncated
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
