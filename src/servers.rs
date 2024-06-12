use crate::schemas::Command;

pub mod http;

mod tcp;
pub use crate::servers::tcp::TcpServer;

mod udp;
pub use crate::servers::udp::UdpServer;

pub trait Server: Send {
    async fn new() -> Self;
    async fn recv(&self) -> Result<Command, String>;
}
