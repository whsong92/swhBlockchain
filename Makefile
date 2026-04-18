# Makefile 예시
.PHONY: build-client build-server run-client run-server clean

build-client:
	cd swhClient && cargo build

build-server:
	cd swhServer && go build -o bin/server main.go

run-client:
	cd swhClient && cargo run

run-server:
	cd swhServer && go run main.go

clean:
	cd swhClient && cargo clean
	cd swhServer && rm -rf bin