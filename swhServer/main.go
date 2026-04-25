package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	pb "swhServer/proto"
	"swhServer/verifier"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Transaction 은 블록에 담길 거래 데이터 구조입니다.
type Transaction struct {
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Amount    float64 `json:"amount"`
}

// Block 은 네트워크를 통해 전파될 블록의 가벼운 정보입니다.
type Block struct {
	Index        int           `json:"index"`
	Timestamp    int64         `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PrevHash     string        `json:"prev_hash"`
	Hash         string        `json:"hash"`
}

// NodeState 는 서버의 현재 상태를 관리합니다.
type NodeState struct {
	sync.Mutex
	Nodes   []string                    // 연결된 다른 피어 노드 목록
	Chain   []Block                     // 로컬 체인 복사본 (조회용)
	Anchors map[string]*pb.AnchorRecord // [신규] 퍼블릭 체인에 기록된 앵커 데이터 (Key -> Record)
}

var state = NodeState{
	Nodes:   []string{},
	Chain:   []Block{},
	Anchors: make(map[string]*pb.AnchorRecord),
}

func main() {
	go startGRPCServer() // gRPC 서버를 별도의 고루틴으로 실행하여 HTTP와 동시 구동

	// API 엔드포인트 설정
	http.HandleFunc("/chain", getChainHandler)              // 전체 체인 조회
	http.HandleFunc("/transactions/new", newTxHandler)      // 새 거래 생성
	http.HandleFunc("/nodes/register", registerNodeHandler) // 피어 노드 등록

	port := ":8081"
	fmt.Printf("✅ swhServer(Go)가 포트 %s에서 실행 중입니다...\n", port)
	fmt.Println("🚀 Rust 클라이언트(swhClient)와 통신할 준비가 되었습니다.")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}

// getChainHandler: 현재 노드가 알고 있는 체인 정보를 반환합니다.
func getChainHandler(w http.ResponseWriter, r *http.Request) {
	state.Lock()
	defer state.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state.Chain)
}

// newTxHandler: 새로운 거래를 생성하고 Rust 클라이언트나 다른 노드에 전파하기 전 대기시킵니다.
func newTxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 메소드만 허용됩니다.", http.StatusMethodNotAllowed)
		return
	}

	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("📩 새 거래 수신: %s -> %s (%.2f)\n", tx.Sender, tx.Recipient, tx.Amount)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "거래가 성공적으로 접수되었습니다.")
}

// registerNodeHandler: 새로운 피어 노드를 네트워크에 추가합니다.
func registerNodeHandler(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Nodes []string `json:"nodes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "잘못된 노드 데이터입니다.", http.StatusBadRequest)
		return
	}

	state.Lock()
	for _, node := range data.Nodes {
		state.Nodes = append(state.Nodes, node)
	}
	state.Unlock()

	fmt.Printf("🌐 새로운 피어 등록됨: %v\n", data.Nodes)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "노드가 성공적으로 등록되었습니다.")
}

// === gRPC 및 mTLS 서버 로직 ===

type grpcServer struct {
	pb.UnimplementedLedgerServiceServer
}

func (s *grpcServer) VerifyCondition(ctx context.Context, req *pb.VerifyLedgerRequest) (*pb.VerifyLedgerResponse, error) {
	log.Printf("📡 VerifyCondition 요청 수신:")
	log.Printf("   - Provider: %s (조건: %s)", req.Condition.ProviderId, req.Condition.ConditionQuery)
	log.Printf("   - User PubKey (Hex): %s", req.UserIdentity.PublicKey)

	isValid, err := verifier.VerifySignature(
		req.UserIdentity.PublicKey,
		req.EncryptedLedgerSnapshot,
		req.UserIdentity.Timestamp,
		req.Condition.ConditionQuery,
		req.UserIdentity.Signature,
	)

	if err != nil {
		log.Printf("❌ 서명 검증 오류: %v", err)
		return &pb.VerifyLedgerResponse{IsValid: false, ErrorMessage: err.Error()}, nil
	}

	if !isValid {
		log.Println("❌ 서명 검증 실패: 위변조된 데이터이거나 잘못된 서명입니다.")
		return &pb.VerifyLedgerResponse{IsValid: false, ErrorMessage: "서명 검증 실패"}, nil
	}

	log.Println("✅ 서명 검증 성공: 무결성이 확인되었습니다.")

	return &pb.VerifyLedgerResponse{
		IsValid:       true,
		TransactionId: "tx_verified_123",
		ErrorMessage:  "",
	}, nil
}

func (s *grpcServer) SubmitTransaction(ctx context.Context, req *pb.SubmitTransactionRequest) (*pb.SubmitTransactionResponse, error) {
	log.Printf("📡 SubmitTransaction 요청 수신:")
	log.Printf("   - Sender PubKey (Hex): %s", req.SenderIdentity.PublicKey)

	// 1. 서명 검증
	isValid, err := verifier.VerifySignature(
		req.SenderIdentity.PublicKey,
		req.TransactionPayload,
		req.SenderIdentity.Timestamp,
		"", // Condition
		req.SenderIdentity.Signature,
	)

	if err != nil || !isValid {
		log.Printf("❌ 트랜잭션 서명 검증 실패: %v", err)
		return &pb.SubmitTransactionResponse{Success: false, BlockHash: ""}, nil
	}

	// 2. Payload 파싱
	var tx Transaction
	if err := json.Unmarshal(req.TransactionPayload, &tx); err != nil {
		log.Printf("❌ 트랜잭션 페이로드 파싱 실패: %v", err)
		return &pb.SubmitTransactionResponse{Success: false, BlockHash: ""}, nil
	}

	// 3. 상태 업데이트 및 앵커링 기록
	state.Lock()
	defer state.Unlock()

	// 앵커 정보가 포함되어 있다면 퍼블릭 체인(Anchors)에 기록
	if req.Anchor != nil {
		log.Printf("🔗 앵커링 기록 중: Key=%s, Hash=%s", req.Anchor.Key, req.Anchor.LedgerHash)
		state.Anchors[req.Anchor.Key] = req.Anchor
	}

	prevHash := "0"
	if len(state.Chain) > 0 {
		prevHash = state.Chain[len(state.Chain)-1].Hash
	}

	newBlockIndex := len(state.Chain)
	hashInput := fmt.Sprintf("%d%d%s%s%s%f", newBlockIndex, req.SenderIdentity.Timestamp, prevHash, tx.Sender, tx.Recipient, tx.Amount)
	hashBytes := sha256.Sum256([]byte(hashInput))
	newBlockHash := hex.EncodeToString(hashBytes[:])

	newBlock := Block{
		Index:        newBlockIndex,
		Timestamp:    req.SenderIdentity.Timestamp,
		Transactions: []Transaction{tx},
		PrevHash:     prevHash,
		Hash:         newBlockHash,
	}

	state.Chain = append(state.Chain, newBlock)
	log.Printf("✅ 트랜잭션 검증 및 블록 생성 완료: 블록 #%d (Hash: %s)", newBlock.Index, newBlock.Hash)

	return &pb.SubmitTransactionResponse{
		Success:   true,
		BlockHash: newBlock.Hash,
	}, nil
}

func (s *grpcServer) GetAnchor(ctx context.Context, req *pb.GetAnchorRequest) (*pb.GetAnchorResponse, error) {
	state.Lock()
	defer state.Unlock()

	anchor, found := state.Anchors[req.Key]
	if !found {
		return &pb.GetAnchorResponse{Found: false}, nil
	}

	return &pb.GetAnchorResponse{Found: true, Anchor: anchor}, nil
}

func startGRPCServer() {
	caCertPath := "/home/wwsong/workspace/swhBlockchain/certs/ca/ca.crt"
	serverCertPath := "/home/wwsong/workspace/swhBlockchain/certs/server/server.crt"
	serverKeyPath := "/home/wwsong/workspace/swhBlockchain/certs/server/server.key"

	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		log.Fatalf("❌ 서버 인증서 로드 실패: %v", err)
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("❌ Root CA 인증서 로드 실패: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caCertPool}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	pb.RegisterLedgerServiceServer(srv, &grpcServer{})

	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("❌ 포트 리스닝 실패: %v", err)
	}

	fmt.Println("✅ swhServer gRPC가 https://localhost:50051 에서 mTLS로 대기 중입니다...")
	if err := srv.Serve(listener); err != nil {
		log.Fatalf("❌ gRPC 서버 실행 실패: %v", err)
	}
}
