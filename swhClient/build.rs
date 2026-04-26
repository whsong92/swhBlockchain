fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 컴파일 시 swh.proto 파일을 읽어와 Rust gRPC 클라이언트 코드를 생성합니다.
    tonic_build::configure()
        .build_server(false) // 클라이언트만 사용할 것이므로 서버 코드 생성 생략
        .compile(&["/home/wwsong/workspace/swhBlockchain/swh.proto"], &["/home/wwsong/workspace/swhBlockchain"])?;
    Ok(())
}