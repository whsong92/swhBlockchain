# swhBlockchain 아키텍처 및 gRPC+mTLS 연동 계획서

본 계획서는 `swhWeb` 프로젝트의 핵심 모듈인 `swhBlockchain`의 클라이언트(Rust)와 서버(Go) 간 통신 및 분산 원장 검증 메커니즘을 구현하기 위한 상세 아키텍처 및 실행 계획입니다.

## 1. 아키텍처 개요 (Architecture Overview)

`swhBlockchain`은 중앙 집중형 데이터베이스를 배제하고, 사용자 디바이스(`swhPersona`)에 분산 저장된 원장(Ledger)을 기반으로 동작합니다. 이를 위해 강력한 상호 인증(mTLS)과 고성능 직렬화 통신(gRPC)이 필수적입니다.

### 1.1. 주요 컴포넌트

*   **swhClient (Rust / swhPersona 내부):**
    *   **로컬 원장 저장소 (Local Ledger Storage):** `sled` 기반의 임베디드 데이터베이스를 사용하여 사용자의 트랜잭션과 상태 정보를 암호화하여 보관.
    *   **지갑 및 서명 모듈 (Wallet & Signer):** 비대칭 키(Public/Private Key) 쌍을 생성하고 원장 데이터 위변조 방지를 위해 모든 요청에 디지털 서명을 수행.
    *   **gRPC 클라이언트 (mTLS 지원):** 서버와 통신하기 위해 클라이언트 인증서를 포함하여 안전한 gRPC 채널 생성.
*   **swhServer (Go):**
    *   **mTLS 종단점 (mTLS Endpoint):** 등록된 클라이언트(자체 CA에서 발급한 인증서 보유자)의 연결만 허용하는 강력한 진입점.
    *   **원장 검증 엔진 (Ledger Verification Engine):** 클라이언트가 보낸 원장 데이터의 서명 유효성, 상태 무결성, 그리고 제공자(Provider)의 요구 조건 충족 여부(True/False)를 판별.
    *   **블록체인 네트워크 (P2P/Consensus):** 검증된 거래 내역을 바탕으로 새로운 블록을 생성하고 다른 노드들에 전파(현재 프로토타입 단계에서는 단일 서버로 가정 후 점진적 확장).
    *   **퍼블릭 앵커링 (Public Anchoring) [향후 과제]:** 상태 증명 해시를 이더리움 등 퍼블릭 블록체인에 주기적으로 기록.

---

## 2. 핵심 데이터 모델 설계 (Data Models - Protobuf)

Rust와 Go 양측 언어에서 완벽히 동일한 구조를 유지하고 역직렬화 성능을 극대화하기 위해 Protocol Buffers(`.proto`)를 사용합니다.

### 2.1. Protobuf 저장소 전략

**[선택 사항 A: Proto 관리 방식]**
*   **A-1. Monorepo 공통 폴더 (선택 완료):** 워크스페이스 루트에 `shared/proto` 디렉토리를 만들어 Rust(`tonic-build`)와 Go(`protoc`)가 빌드 타임에 동일한 파일을 참조하도록 설정.

### 2.2. 주요 메세지 구조 (예시: `swh.proto`)

```protobuf
syntax = "proto3";

package swh.blockchain.v1;
option go_package = "swhServer/proto;swh_pb";

// 사용자 지갑 및 서명 정보
message Identity {
  string public_key = 1;     // 사용자의 공개키 (Ed25519 또는 Secp256k1)
  bytes signature = 2;       // Payload 전체에 대한 전자 서명값
  int64 timestamp = 3;       // 재전송 공격(Replay Attack) 방지용 타임스탬프
}

// 서비스 제공자가 검증을 요청하는 조건
message ProviderCondition {
  string provider_id = 1;
  string condition_query = 2; // 예: "age >= 19 AND balance >= 1000"
}

// 원장 검증 요청 페이로드
message VerifyLedgerRequest {
  Identity user_identity = 1;
  bytes encrypted_ledger_snapshot = 2; // 증명에 필요한 최소한의 원장 상태 스냅샷
  ProviderCondition condition = 3;
}

// 원장 검증 응답
message VerifyLedgerResponse {
  bool is_valid = 1;         // 조건 부합 여부 (True/False)
  string transaction_id = 2; // 검증 이력 추적용 ID
  string error_message = 3;  // 실패 시 사유
}

// 새로운 거래(상태 변경) 요청
message SubmitTransactionRequest {
  Identity sender_identity = 1;
  Identity receiver_identity = 2; // 수신자가 있을 경우
  bytes transaction_payload = 3;  // 전송 금액 또는 상태 변경 내역 (JSON 등)
}

// 새로운 거래 응답
message SubmitTransactionResponse {
  bool success = 1;
  string block_hash = 2;          // 거래가 포함될(또는 포함된) 블록의 해시
}

service LedgerService {
  // 제공자의 조건에 맞는지 원장 상태를 검증
  rpc VerifyCondition (VerifyLedgerRequest) returns (VerifyLedgerResponse);
  
  // 상태 변경 및 거래 전송
  rpc SubmitTransaction (SubmitTransactionRequest) returns (SubmitTransactionResponse);
}
```

---

## 3. 보안 및 암호화 설계 (Security & Cryptography)

### 3.1. mTLS (상호 TLS) 아키텍처

일반적인 웹 통신은 클라이언트가 서버의 신원만 확인하지만, 원장이라는 극비 데이터를 다루는 `swhWeb`은 서버 또한 클라이언트(swhPersona)의 신원을 검증해야 합니다.

**[선택 사항 B: CA (Certificate Authority) 구축 방식]**
*   **B-1. 자체 Root CA (선택 완료):** `swhWeb` 자체적으로 인증기관 역할을 수행. 서버 구동 시 Root CA 및 Server 인증서를 생성하고, 클라이언트(`swhClient`)가 최초 등록 시 고유한 Client 인증서를 발급받아 이후 통신에 사용.

### 3.2. 전자 서명 알고리즘 선택

사용자가 자신의 디바이스에서 원장에 서명할 때 사용할 비대칭 키 알고리즘입니다.

**[선택 사항 C: 암호화 알고리즘]**
*   **C-1. Ed25519 (선택 완료):** 빠르고 안전하며 최신 분산 시스템 및 Rust/Tauri 환경에 매우 적합.

---

## 4. 단계별 구현 플랜 (Implementation Phases)

### Phase 1: 기반 인프라 구성 (gRPC & Proto) - 완료
1. `shared/proto` 디렉토리 생성 및 `swh.proto` 작성. (완료)
2. **Go Server (`swhServer`):** `protoc` 플러그인 설치 및 `gen_proto.sh` 스크립트 작성. (완료)
3. **Rust Client (`swhClient`):** `tonic-build` 의존성 추가 및 `build.rs` 컴파일 연동. (완료)

### Phase 2: 암호화 및 mTLS 적용 - 완료
1. **자체 CA 구성용 인증서 스크립트 작성:** `certs/gen_certs.sh` 및 `openssl.cnf` 작성. (완료)
2. **Go Server mTLS 적용:** `main.go`에 `tls.RequireAndVerifyClientCert` 옵션을 포함한 gRPC 서버 구현. (완료)
3. **Rust Client mTLS 적용:** `main.rs`에 `tonic::transport::ClientTlsConfig`를 사용하여 서버에 mTLS 연결 구현. (완료)

### Phase 3: 로컬 원장 저장 및 서명 로직 구현
1. **Rust Client 서명 모듈:** 선택된 알고리즘(`ed25519-dalek`)을 사용하여 키 쌍 생성 및 안전한 보관. 요청 데이터 포맷팅 및 서명 로직 추가.
2. **Rust Client 원장 연동:** `sled` DB에 저장된 상태(Balance 등)를 읽어와 서명 후 `SubmitTransaction` 또는 `VerifyCondition` gRPC 호출.
3. **Go Server 검증 로직:** 수신된 서명 데이터(`Identity`) 복호화 및 유효성 검증. 조작되지 않은 데이터임을 확정한 후 로직 처리.

### Phase 4: 오프라인/다중 기기 동기화 테스트 (추후 확장)
1. 메인 기기와 서브 기기 간의 분할 원장(Temporary Ledger) 개념을 자료구조에 추가.
2. 서버 측 임시 상태 버퍼 저장소 구현.

---

## 5. 승인 요청 사항 (Action Required)

플랜을 실행하기 전, 다음 항목들에 대한 선택이 필요합니다.

1. **Proto 관리 방식 (A):** 모노레포 내 `shared/proto` 공유 (선택 완료)
2. **mTLS CA 방식 (B):** 자체 스크립트 기반 Root CA (선택 완료)
3. **암호화 알고리즘 (C):** Ed25519 (선택 완료)

결정해 주시면 즉시 코드를 작성하여 반영하겠습니다!

---

## 6. 현재 진행 상황 및 향후 계획 (Current Status & Future Tasks)

### 📌 현재 진행 상황 (Current Status)
- **Phase 1 (기반 인프라):** `shared/proto`를 통한 gRPC Protobuf 단일 진실 공급원 구성 및 Go/Rust 빌드 연동 완료.
- **Phase 2 (mTLS 적용):** 자체 Root CA 기반 인증서 발급 스크립트 작성 및 Go-Rust 간 양방향 상호 인증(mTLS) 연결 완료.
- **Phase 3 (암호화 로직 진행 중):** 
  - **Rust 클라이언트 (`swhClient`):** `ed25519-dalek`을 활용한 지갑 키 쌍 생성 및 타임스탬프, 페이로드를 조합한 전자 서명 로직 구현 완료.
  - **Go 서버 (`swhServer`):** 수신된 요청의 Ed25519 서명 유효성 검증(Verify) 로직 및 mTLS/HTTP 동시 구동 환경(Goroutine) 구성 완료.

### 🚀 앞으로 해야 할 일 (Future Tasks / Action Items)

1. **서명/검증 모듈화 (Refactoring):** 현재 `main.rs`와 `main.go`에 절차적으로 작성되어 있는 서명/검증 로직을 재사용 가능한 별도의 파일/패키지로 분리합니다.
2. **로컬 DB 연동 (Rust Client):** `sled` 임베디드 데이터베이스를 연동하여 사용자의 원장 상태(Ledger Snapshot)와 암호화 키 쌍을 로컬 파일 시스템에 안전하게 영구 저장(Persist)하고 조회하는 기능을 추가합니다.
3. **트랜잭션 검증 및 블록화 (Go Server):** `SubmitTransaction` gRPC API를 마저 구현하여 실제 거래 내역을 수신/검증하고, 서버 내 메모리 상태(`state.Chain`)에 신규 블록으로 업데이트하는 로직을 완성합니다.
4. **통합 테스트 및 예외 처리 (Test & Error Handling):** 네트워크 단절, 악의적인 서명 데이터 등 예외 상황에 대한 견고한 에러 핸들링을 구성합니다.
5. **Phase 4 (심화 과제) 준비:** 다중 기기(메인-서브) 동기화 및 오프라인 상태를 위한 임시 분할 원장(Temporary Ledger) 설계 및 구현에 착수합니다.
