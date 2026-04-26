use ed25519_dalek::{SigningKey, Signer, Signature};
use std::time::{SystemTime, UNIX_EPOCH};

/// 서명 생성 및 키 관리를 담당하는 모듈
pub struct CryptoSigner;

impl CryptoSigner {
    /// Payload, Timestamp, Condition을 조합하여 Ed25519 서명을 생성합니다.
    pub fn sign_data(signing_key: &SigningKey, payload: &[u8], condition: &str) -> (Vec<u8>, i64) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // 서명할 원본 메시지 조립
        let mut msg = payload.to_vec();
        msg.extend_from_slice(timestamp.to_string().as_bytes());
        if !condition.is_empty() {
            msg.extend_from_slice(condition.as_bytes());
        }

        // 전자 서명 수행
        let signature: Signature = signing_key.sign(&msg);
        (signature.to_bytes().to_vec(), timestamp)
    }

    /// SigningKey에서 공개키를 추출하여 Hex 문자열로 반환합니다.
    pub fn get_public_key_hex(signing_key: &SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }
}