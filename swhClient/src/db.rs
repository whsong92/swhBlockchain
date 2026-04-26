use sled::Db;
use std::path::Path;

const KEYPAIR_ENC_KEY: &str = "encrypted_identity_keypair";
const SALT_KEY: &str = "kdf_salt";
const NONCE_KEY: &str = "encryption_nonce";
const LEDGER_STATE_KEY: &str = "ledger_snapshot";

/// 클라이언트 로컬 데이터베이스 관리 구조체
pub struct LocalStorage {
    db: Db,
}

impl LocalStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// 암호화된 키 쌍과 관련 메타데이터(솔트, 넌스)를 저장합니다.
    pub fn save_encrypted_keypair(&self, encrypted_bytes: &[u8], salt: &[u8], nonce: &[u8]) -> Result<(), sled::Error> {
        self.db.insert(KEYPAIR_ENC_KEY, encrypted_bytes)?;
        self.db.insert(SALT_KEY, salt)?;
        self.db.insert(NONCE_KEY, nonce)?;
        self.db.flush()?;
        Ok(())
    }

    /// 암호화된 키 쌍 데이터를 불러옵니다.
    pub fn load_security_data(&self) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>, sled::Error> {
        let enc_key = self.db.get(KEYPAIR_ENC_KEY)?;
        let salt = self.db.get(SALT_KEY)?;
        let nonce = self.db.get(NONCE_KEY)?;

        if let (Some(k), Some(s), Some(n)) = (enc_key, salt, nonce) {
            Ok(Some((k.to_vec(), s.to_vec(), n.to_vec())))
        } else {
            Ok(None)
        }
    }

    /// 가입 여부를 확인합니다 (키 존재 여부).
    pub fn is_registered(&self) -> bool {
        self.db.get(KEYPAIR_ENC_KEY).unwrap_or(None).is_some()
    }

    pub fn save_ledger_snapshot(&self, snapshot_bytes: &[u8]) -> Result<(), sled::Error> {
        self.db.insert(LEDGER_STATE_KEY, snapshot_bytes)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn load_ledger_snapshot(&self) -> Result<Option<sled::IVec>, sled::Error> {
        self.db.get(LEDGER_STATE_KEY)
    }
}