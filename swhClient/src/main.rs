pub mod swh_pb {
    tonic::include_proto!("swh.blockchain.v1");
}

mod signer;
mod security;
mod db;

use swh_pb::ledger_service_client::LedgerServiceClient;
use swh_pb::{VerifyLedgerRequest, ProviderCondition, Identity, SubmitTransactionRequest};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
use std::fs;

use db::LocalStorage;
use signer::CryptoSigner;
use security::SecurityManager;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 swhClient 시작 - mTLS 및 보안 스택 설정 중...");

    let test_password = "swh_persona_test_password";

    // 1. 인증서 설정 (컴파일 시점에 바이너리에 포함)
    let ca_cert_pem = include_bytes!("../../certs/ca/ca.crt");
    let client_cert_pem = include_bytes!("../../certs/client/client.crt");
    let client_key_pem = include_bytes!("../../certs/client/client.key");

    let tls_config = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(ca_cert_pem))
        .identity(TlsIdentity::from_pem(client_cert_pem, client_key_pem));

    let channel = Channel::from_static("https://localhost:50051")
        .tls_config(tls_config)?
        .connect()
        .await?;

    println!("✅ 서버에 mTLS 보안 연결 완료!");

    let mut client = LedgerServiceClient::new(channel);

    // 2. 보안 DB에서 지갑 로드 (암호화 방식 적용)
    let storage = LocalStorage::new(".swh_data")?;
    
    let signing_key = match storage.load_security_data()? {
        Some((ciphertext, salt, nonce)) => {
            println!("📂 암호화된 지갑을 발견했습니다. 복호화 중...");
            let master_key = SecurityManager::derive_key(test_password, &salt)?;
            let key_bytes = SecurityManager::decrypt(&ciphertext, &master_key, &nonce)?;
            SigningKey::from_bytes(&key_bytes.as_slice().try_into()?)
        }
        None => {
            println!("✨ 신규 지갑 생성 및 암호화 저장 중...");
            let mut csprng = OsRng;
            let new_key = SigningKey::generate(&mut csprng);
            let salt = SecurityManager::generate_salt();
            let master_key = SecurityManager::derive_key(test_password, &salt)?;
            let (nonce, ciphertext) = SecurityManager::encrypt(&new_key.to_bytes(), &master_key)?;
            
            storage.save_encrypted_keypair(&ciphertext, &salt, &nonce)?;
            new_key
        }
    };

    let pubkey_hex = CryptoSigner::get_public_key_hex(&signing_key);
    println!("🔑 나의 공개키: {}", pubkey_hex);

    // 3. 테스트 요청
    let snapshot = vec![10, 20, 30];
    let condition_query = "age >= 19".to_string();

    let (signature, timestamp) = CryptoSigner::sign_data(&signing_key, &snapshot, &condition_query);

    let request = tonic::Request::new(VerifyLedgerRequest {
        user_identity: Some(Identity {
            public_key: pubkey_hex.clone(),
            signature,
            timestamp,
        }),
        encrypted_ledger_snapshot: snapshot,
        condition: Some(ProviderCondition {
            provider_id: "Provider_A".to_string(),
            condition_query,
        }),
    });

    println!("📡 VerifyCondition 요청 전송...");
    if let Ok(response) = client.verify_condition(request).await {
        let res = response.into_inner();
        println!("🎉 결과: valid={}, tx_id={}", res.is_valid, res.transaction_id);
    }

    // SubmitTransaction 테스트 (서버가 기대하는 JSON 형식으로 전송)
    let tx_payload = r#"{"sender": "user_a", "recipient": "user_b", "amount": 100.0}"#.as_bytes().to_vec();
    let (tx_sig, tx_ts) = CryptoSigner::sign_data(&signing_key, &tx_payload, "");
    
    let tx_request = tonic::Request::new(SubmitTransactionRequest {
        sender_identity: Some(Identity {
            public_key: pubkey_hex,
            signature: tx_sig,
            timestamp: tx_ts,
        }),
        transaction_payload: tx_payload,
        anchor: None,
    });

    println!("\n📡 SubmitTransaction 요청 전송...");
    if let Ok(response) = client.submit_transaction(tx_request).await {
        let res = response.into_inner();
        println!("🎉 결과: success={}, block_hash={}", res.success, res.block_hash);
    }

    // HTTP 체인 조회
    println!("\n🌐 체인 상태 확인 (HTTP)...");
    if let Ok(res) = reqwest::get("http://localhost:8081/chain").await {
        println!("📦 응답 코드: {}", res.status());
    }

    Ok(())
}