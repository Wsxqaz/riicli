use crate::schemas::{ Command, Host };
use crate::servers::Server;
use crate::constants::UDP_BIND_ADDR;
use tokio::net::UdpSocket;
use tokio::io::AsyncReadExt;
use futures::future::FutureExt;

pub struct UdpServer {
    socket: UdpSocket,
}

impl Server for UdpServer {
    async fn new() -> Self {
        let socket = UdpSocket::bind(UDP_BIND_ADDR).await.unwrap();
        UdpServer { socket }
    }

    async fn recv(&self) -> Result<Command, String> {
        let mut buf = [0; 1024];
        let _recv = self.socket.recv_from(&mut buf).await;
        let host = Host::from(buf.to_vec());
        Ok(Command::CheckIn(host))
    }
}
