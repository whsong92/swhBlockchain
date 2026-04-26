use argon2::Argon2;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};

pub struct SecurityManager;

impl SecurityManager {
    /// 비밀번호와 솔트를 사용하여 256비트 암호화 키를 도출합니다 (Argon2id).
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| format!("KDF Error: {}", e))?;
        Ok(key)
    }

    /// 데이터를 AES-256-GCM으로 암호화합니다. (Nonce + Ciphertext 반환)
    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("Encryption Error: {}", e))?;

        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// 암호화된 데이터를 복호화합니다.
    pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption Error: {}", e))?;

        Ok(plaintext)
    }

    /// 새로운 솔트를 생성합니다.
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }
}
