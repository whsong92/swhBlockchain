use napi_derive::napi;
use napi::bindgen_prelude::*;

pub mod swh_pb {
    tonic::include_proto!("swh.blockchain.v1");
}

mod signer;
mod security;
mod db;

use swh_pb::ledger_service_client::LedgerServiceClient;
use swh_pb::{Identity, SubmitTransactionRequest};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
use std::fs;
use std::sync::Arc;
use tokio::sync::Mutex;

use db::LocalStorage;
use signer::CryptoSigner;
use security::SecurityManager;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[napi]
pub struct SwhCore {
    storage: LocalStorage,
    signing_key: Arc<Mutex<Option<SigningKey>>>,
}

#[napi]
impl SwhCore {
    #[napi(constructor)]
    pub fn new(db_path: String) -> Result<Self> {
        let storage = LocalStorage::new(&db_path)
            .map_err(|e| Error::from_reason(format!("DB 초기화 실패: {}", e)))?;
        
        Ok(Self {
            storage,
            signing_key: Arc::new(Mutex::new(None)),
        })
    }

    #[napi]
    pub async fn login(&self, password: String) -> Result<String> {
        let security_data = self.storage.load_security_data()
            .map_err(|e| Error::from_reason(format!("보안 데이터 로드 실패: {}", e)))?;

        let key = match security_data {
            Some((ciphertext, salt, nonce)) => {
                let master_key = SecurityManager::derive_key(&password, &salt)
                    .map_err(|e| Error::from_reason(format!("키 도출 실패: {}", e)))?;
                let key_bytes = SecurityManager::decrypt(&ciphertext, &master_key, &nonce)
                    .map_err(|e| Error::from_reason(format!("복호화 실패: {}", e)))?;
                SigningKey::from_bytes(&key_bytes.as_slice().try_into().map_err(|_| Error::from_reason("잘못된 키 길이"))?)
            }
            None => return Err(Error::from_reason("지갑을 찾을 수 없습니다. 먼저 등록해주세요.")),
        };

        let pubkey_hex = CryptoSigner::get_public_key_hex(&key);
        let mut lock = self.signing_key.lock().await;
        *lock = Some(key);

        Ok(pubkey_hex)
    }

    #[napi]
    pub async fn register(&self, password: String) -> Result<String> {
        let mut csprng = OsRng;
        let new_key = SigningKey::generate(&mut csprng);
        let salt = SecurityManager::generate_salt();
        let master_key = SecurityManager::derive_key(&password, &salt)
            .map_err(|e| Error::from_reason(e))?;
        let (nonce, ciphertext) = SecurityManager::encrypt(&new_key.to_bytes(), &master_key)
            .map_err(|e| Error::from_reason(e))?;
        
        self.storage.save_encrypted_keypair(&ciphertext, &salt, &nonce)
            .map_err(|e| Error::from_reason(format!("지갑 저장 실패: {}", e)))?;

        let pubkey_hex = CryptoSigner::get_public_key_hex(&new_key);
        let mut lock = self.signing_key.lock().await;
        *lock = Some(new_key);

        Ok(pubkey_hex)
    }

    #[napi]
    pub async fn submit_transaction(&self, payload_json: String) -> Result<String> {
        let lock = self.signing_key.lock().await;
        let signing_key = lock.as_ref().ok_or_else(|| Error::from_reason("로그인이 필요합니다."))?;

        let ca_cert_path = "/home/wwsong/workspace/swhBlockchain/certs/ca/ca.crt";
        let client_cert_path = "/home/wwsong/workspace/swhBlockchain/certs/client/client.crt";
        let client_key_path = "/home/wwsong/workspace/swhBlockchain/certs/client/client.key";

        let ca_cert_pem = fs::read(ca_cert_path).map_err(|e| Error::from_reason(e.to_string()))?;
        let client_cert_pem = fs::read(client_cert_path).map_err(|e| Error::from_reason(e.to_string()))?;
        let client_key_pem = fs::read(client_key_path).map_err(|e| Error::from_reason(e.to_string()))?;

        let tls_config = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(ca_cert_pem))
            .identity(TlsIdentity::from_pem(client_cert_pem, client_key_pem));

        let channel = Channel::from_static("https://localhost:50051")
            .tls_config(tls_config).map_err(|e| Error::from_reason(e.to_string()))?
            .connect()
            .await.map_err(|e| Error::from_reason(format!("서버 연결 실패: {}", e)))?;

        let mut client = LedgerServiceClient::new(channel);
        let payload_bytes = payload_json.into_bytes();
        let (signature, timestamp) = CryptoSigner::sign_data(signing_key, &payload_bytes, "");

        let pubkey_hex = CryptoSigner::get_public_key_hex(signing_key);
        let request = tonic::Request::new(SubmitTransactionRequest {
            sender_identity: Some(Identity {
                public_key: pubkey_hex,
                signature,
                timestamp,
            }),
            transaction_payload: payload_bytes,
            anchor: None,
        });

        let response = client.submit_transaction(request).await
            .map_err(|e| Error::from_reason(format!("트랜잭션 제출 실패: {}", e)))?;
        
        let res = response.into_inner();
        if res.success {
            Ok(res.block_hash)
        } else {
            Err(Error::from_reason("서버에서 트랜잭션 처리에 실패했습니다."))
        }
    }
}
