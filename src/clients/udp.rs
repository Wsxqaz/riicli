use crate::constants::UDP_BIND_ADDR;
use crate::schemas::Host;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

pub async fn client() {
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let host = Host {
        hostname: "example.com".to_string(),
        ip: "127.0.0.1".to_string(),
    };
    let buf = Vec::from(host);
    let r = udp_socket.send_to(&buf, UDP_BIND_ADDR).await.unwrap();
    log::info!("Sent {} bytes", r);
}
