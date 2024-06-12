use crate::constants::{TCP_BIND_ADDR, UDP_BIND_ADDR};
use crate::schemas::{Command, Host};
use crate::servers::{ Server, TcpServer, UdpServer };
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub async fn run_server() {
    let (tx, _rx) = mpsc::channel();

    let tcp_server = TcpServer::new().await;
    log::info!("TCP Server started");
    let udp_server = UdpServer::new().await;
    log::info!("UDP Server started");

    loop {
        let tx = tx.clone();
        tokio::select! {
            udp_cmd = udp_server.recv() => {
                match udp_cmd {
                    Ok(cmd) => {
                        log::info!("Received cmd via udp: {:?}", cmd);
                        let _ = tx.clone().send(cmd);
                    }
                    Err(e) => {
                        log::info!("Failed to read from socket; err = {:?}", e);
                    }
                }
            }
            tcp_cmd = tcp_server.recv() => {
                match tcp_cmd {
                    Ok(cmd) => {
                        log::info!("Received cmd via tcp: {:?}", cmd);
                        let _ = tx.clone().send(cmd);
                    }
                    Err(e) => {
                        log::info!("Failed to read from socket; err = {:?}", e);
                    }
                }
            }
        }
    }
}
