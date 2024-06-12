use crate::constants::TCP_BIND_ADDR;
use crate::schemas::Host;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub async fn client() {
    let mut stream = TcpStream::connect(TCP_BIND_ADDR).await.unwrap();
    let host = Host {
        hostname: "example.com".to_string(),
        ip: "127.0.0.1".to_string(),
    };
    let buf = Vec::from(host);
    let r = stream.write(&buf).await.unwrap();
    log::info!("Sent {} bytes", r);
}
