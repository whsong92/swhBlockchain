package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
)

// VerifySignature 는 주어진 공개키를 사용해 데이터의 Ed25519 서명 유효성을 검증합니다.
func VerifySignature(pubKeyHex string, payload []byte, timestamp int64, condition string, signatureBytes []byte) (bool, error) {
	// 1. Hex 문자열로 전달된 공개키를 바이트 배열로 디코딩
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("유효하지 않은 공개키 Hex 형식입니다: %v", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, errors.New("공개키 길이가 잘못되었습니다 (Ed25519는 32바이트여야 함)")
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// 2. 서명에 사용된 원본 메시지 재구성 (Payload + Timestamp + Condition)
	msg := append([]byte{}, payload...)
	msg = append(msg, []byte(fmt.Sprintf("%d", timestamp))...)
	if condition != "" {
		msg = append(msg, []byte(condition)...)
	}

	// 3. 서명 검증 수행
	isValid := ed25519.Verify(pubKey, msg, signatureBytes)
	return isValid, nil
}
