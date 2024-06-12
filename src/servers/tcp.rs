use crate::schemas::{ Command, Host };
use crate::servers::Server;
use crate::constants::TCP_BIND_ADDR;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, Interest};
use futures::future::FutureExt;

pub struct TcpServer {
    listener: TcpListener,
}

async fn handle_client(stream: tokio::net::TcpStream) -> Result<Command, String> {
    let mut buf = [0u8; 1024];
    let ready = stream.ready(Interest::READABLE).await.unwrap();
    if ready.is_readable() {
        log::info!("Reading from socket");
        match stream.try_read(&mut buf) {
            Ok(n) => {
                let command = Command::CheckIn(Host::from(buf[..n].to_vec()));
                log::info!("Received command: {:?}", command);
                Ok(command)
            }
            Err(e) => {
                let msg = format!("Failed to read from socket; err = {:?}", e);
                log::info!("{}", msg);
                Err(msg)
            }
        }
    } else {
        let msg = "Socket not readable".to_owned();
        log::info!("{}", msg);
        Err(msg)
    }
}

impl Server for TcpServer {
    async fn new() -> Self {
        let listener = TcpListener::bind(TCP_BIND_ADDR).await.unwrap();
        TcpServer { listener }
    }

    async fn recv(&self) -> Result<Command, String> {
        let stream = self.listener.accept().await;
        match stream {
            Ok((stream, _)) => handle_client(stream).await,
            Err(e) => {
                let msg = format!("Failed to accept socket; err = {:?}", e);
                log::info!("{}", msg);
                Err(msg)
            }
        }
    }
}
