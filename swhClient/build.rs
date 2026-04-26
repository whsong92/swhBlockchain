fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 컴파일 시 swh.proto 파일을 읽어와 Rust gRPC 클라이언트 코드를 생성합니다.
    tonic_build::configure()
        .build_server(false)
        .compile(&["../swh.proto"], &[".."])?;
    Ok(())
}