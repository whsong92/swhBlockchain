#!/bin/bash

# swhBlockchain mTLS 인증서 생성 스크립트
#
# 사용법:
# ./certs/gen_certs.sh
#
# 생성되는 파일:
# - certs/ca/ca.key: Root CA 개인키
# - certs/ca/ca.crt: Root CA 인증서
# - certs/server/server.key: 서버 개인키
# - certs/server/server.crt: 서버 인증서 (localhost용)
# - certs/client/client.key: 클라이언트 개인키
# - certs/client/client.crt: 클라이언트 인증서

set -e
cd "$(dirname "$0")"

# --- 디렉토리 생성 ---
mkdir -p ca server client

# --- 1. Root CA 생성 ---
echo "🔐 1. Root CA 개인키 및 인증서 생성 중..."
openssl genpkey -algorithm RSA -out ca/ca.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key ca/ca.key -out ca/ca.crt -days 3650 \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=swhWeb/OU=swhBlockchain CA/CN=swhBlockchain Root CA" \
    -config openssl.cnf \
    -extensions v3_ca

echo "✅ Root CA 생성 완료: ca/ca.crt"
echo ""

# --- 2. 서버 인증서 생성 (localhost) ---
echo "🔐 2. 서버 개인키 및 인증서 생성 중 (for localhost)..."
openssl genpkey -algorithm RSA -out server/server.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key server/server.key -out server/server.csr -subj "/C=KR/ST=Seoul/L=Seoul/O=swhWeb/OU=swhServer/CN=localhost"
openssl x509 -req -in server/server.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -out server/server.crt -days 365 -extfile openssl.cnf -extensions v3_server
rm server/server.csr
echo "✅ 서버 인증서 생성 완료: server/server.crt"
echo ""

# --- 3. 클라이언트 인증서 생성 ---
echo "🔐 3. 클라이언트 개인키 및 인증서 생성 중..."
openssl genpkey -algorithm RSA -out client/client.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key client/client.key -out client/client.csr -subj "/C=KR/ST=Seoul/L=Seoul/O=swhWeb/OU=swhClient/CN=swhClientUser"
openssl x509 -req -in client/client.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -out client/client.crt -days 365 -extfile openssl.cnf -extensions v3_client
rm client/client.csr
echo "✅ 클라이언트 인증서 생성 완료: client/client.crt"
echo ""

echo "🎉 모든 인증서 생성이 완료되었습니다."