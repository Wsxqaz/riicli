#[derive(Debug)]
pub struct Host {
    pub hostname: String,
    pub ip: String,
}

#[derive(Debug)]
pub enum Command {
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
        let mut ip = String::from_utf8(parts.next().unwrap().to_vec()).unwrap();
        ip.retain(|c| c != '\0');
        Self { hostname, ip }
    }
}
