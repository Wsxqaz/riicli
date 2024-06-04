use std::sync::{ mpsc, Arc, Mutex };
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket };
use tokio::io::AsyncWriteExt;
use tokio::io::Interest;

#[derive(Debug)]
struct Host {
    hostname: String,
    ip: String,
}

#[derive(Debug)]
enum Command {
    CheckIn(Host),
}

impl From<Host> for Vec<u8> {
    fn from(host: Host) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(host.hostname.as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(host.ip.as_bytes());
        buf
    }
}

impl From<Vec<u8>> for Host {
    fn from(buf: Vec<u8>) -> Self {
        let mut parts = buf.split(|&b| b == b' ');
        let hostname = String::from_utf8(parts.next().unwrap().to_vec()).unwrap();
        let ip = String::from_utf8(parts.next().unwrap().to_vec()).unwrap();
        Self { hostname, ip }
    }
}

const TCP_BIND_ADDR: &str = "127.0.0.1:8086";

pub async fn run_udp_client() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let host = Host {
        hostname: "example.com".to_string(),
        ip: "127.0.0.1".to_string(),
    };
    let buf = Vec::from(host);
    let r = udp_socket.send_to(&buf, "127.0.0.1:5353").await.unwrap();
    log::info!("Sent {} bytes", r);
}

pub async fn run_tcp_client() {
    let mut stream = TcpStream::connect(TCP_BIND_ADDR).await.unwrap();
    let host = Host {
        hostname: "example.com".to_string(),
        ip: "127.0.0.1".to_string(),
    };
    let buf = Vec::from(host);
    let r = stream.write(&buf).await.unwrap();
    log::info!("Sent {} bytes", r);
}

pub async fn run_server() {
    // let udp_socket = UdpSocket::bind("127.0.0.1:5353").await.unwrap();
    let tcp_listener = TcpListener::bind(TCP_BIND_ADDR).await.unwrap();
    log::info!("Listening on {}", TCP_BIND_ADDR);
    let (tx, _rx) = mpsc::channel();

    let mut udp_buf = [0u8; 1024];

    loop {
        let tx = tx.clone();
        tokio::select! {
            // udp_packet = udp_socket.recv_from(&mut udp_buf) => {
            //     log::info!("Received UDP packet");
            //     let (_amt, _src) = udp_packet.unwrap();
            //     let host = Host::from(udp_buf.to_vec());
            //     let _ = tx.clone().send(Command::CheckIn(host));
            // }
            tcp_stream = tcp_listener.accept() => {
                let (stream, _addr) = tcp_stream.unwrap();
                log::info!("Accepted TCP connection");
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let ready = stream.ready(Interest::READABLE).await.unwrap();
                    if ready.is_readable() {
                        log::info!("Reading from socket");
                        match stream.try_read(&mut buf) {
                            Ok(n) => {
                                let command = Command::CheckIn(Host::from(buf[..n].to_vec()));
                                log::info!("Received command: {:?}", command);
                                let _ = tx.clone().send(Command::CheckIn(Host::from(buf[..n].to_vec())));
                            }
                            Err(e) => {
                                log::info!("Failed to read from socket; err = {:?}", e);
                            }
                        }
                    } else {
                        log::info!("Socket not readable");
                    }
                });
            }
        }
    }
}
