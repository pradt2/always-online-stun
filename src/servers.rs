use std::path::PathBuf;
use tokio::io;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransportProtocol {
    UDP, TCP
}

#[derive(Clone, Debug)]
pub struct StunServer {
    pub protocol: TransportProtocol,
    pub hostname: String,
    pub port: u16,
}

pub async fn get_stun_servers(filepath: PathBuf) -> io::Result<Vec<StunServer>> {
    let stun_servers = tokio::fs::read_to_string(filepath).await?
        .split('\n')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter(|s| !s.starts_with('#'))
        .filter(|s| !s.starts_with("//"))
        .map(|stun_server_str| {
            let (hostname, port) = stun_server_str.split_once(':').unwrap();
            StunServer {
                protocol: TransportProtocol::UDP,
                hostname: String::from(hostname),
                port: port.parse().unwrap()
            }
        }).collect::<Vec<_>>();
    return Ok(stun_servers);
}
