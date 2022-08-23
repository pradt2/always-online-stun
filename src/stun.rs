use std::net::{SocketAddr};
use std::time::{Duration, Instant};
use stunclient::Error;
use tokio::net::UdpSocket;
use crate::utils::join_all_with_semaphore;
use crate::StunServer;

#[derive(Clone, Debug)]
pub(crate) struct StunServerTestResult {
    pub(crate) server: StunServer,
    pub(crate) socket_tests: Vec<StunSocketTestResult>,
}

impl StunServerTestResult {
    pub(crate) fn is_resolvable(&self) -> bool {
        return self.socket_tests.len() > 0;
    }

    pub(crate) fn is_healthy(&self) -> bool {
        self.is_resolvable() && self.socket_tests.iter()
            .all(StunSocketTestResult::is_ok)
    }

    pub(crate) fn is_partial_timeout(&self) -> bool {
        self.is_resolvable()
            && self.is_any_healthy()
            && self.is_any_timeout()
            && !self.is_any_invalid_mapping()
            && !self.is_any_unexpected_response()
    }

    pub(crate) fn is_timeout(&self) -> bool {
        self.is_resolvable()
            && !self.is_any_healthy()
            && self.is_any_timeout()
            && !self.is_any_invalid_mapping()
            && !self.is_any_unexpected_response()
    }

    fn is_any_healthy(&self) -> bool {
        self.is_resolvable() && self.socket_tests.iter()
            .any(|result| match result.result {
                StunSocketResponse::HealthyResponse { .. } => true,
                _ => false,
            })
    }

    fn is_any_timeout(&self) -> bool {
        self.is_resolvable() && self.socket_tests.iter()
            .any(|result| match result.result {
                StunSocketResponse::Timeout { .. } => true,
                _ => false,
            })
    }

    fn is_any_invalid_mapping(&self) -> bool {
        self.is_resolvable() && self.socket_tests.iter()
            .any(|result| match result.result {
                StunSocketResponse::InvalidMappingResponse { .. } => true,
                _ => false,
            })
    }

    fn is_any_unexpected_response(&self) -> bool {
        self.is_resolvable() && self.socket_tests.iter()
            .any(|result| match result.result {
                StunSocketResponse::UnexpectedError { .. } => true,
                _ => false,
            })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StunSocketTestResult {
    pub(crate) socket: SocketAddr,
    pub(crate) result: StunSocketResponse,
}

impl StunSocketTestResult {
    pub(crate) fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum StunSocketResponse {
    HealthyResponse { rtt: Duration },
    InvalidMappingResponse { expected: SocketAddr, actual: SocketAddr, rtt: Duration },
    Timeout { deadline: Duration },
    UnexpectedError { err: String },
}

impl StunSocketResponse {
    fn is_ok(&self) -> bool {
        match &self {
            StunSocketResponse::HealthyResponse { .. } => true,
            _ => false
        }
    }
}

pub(crate) async fn test_udp_stun_server(
    server: StunServer,
    behind_nat: bool,
) -> StunServerTestResult {
    let socket_addrs = tokio::net::lookup_host(format!("{}:{}", server.hostname, server.port)).await;

    if socket_addrs.is_err() {
        let err_str = socket_addrs.as_ref().err().unwrap().to_string();
        if err_str.contains("Name or service not known") ||
            err_str.contains("No address associated with hostname") {} else {
            warn!("{:<21} -> Unexpected DNS failure: {}", server.hostname, socket_addrs.as_ref().err().unwrap().to_string());
        }
        return StunServerTestResult {
            server,
            socket_tests: vec![],
        };
    }

    let results = socket_addrs.unwrap()
        .map(|addr| addr.ip())
        .map(|addr| {
            let port = server.port;
            let hostname = server.hostname.as_str();
            async move {
                let stun_socket = SocketAddr::new(addr, port);
                let res = if behind_nat {
                    test_socket_addr_against_trusted_party(hostname, stun_socket).await
                } else {
                    test_socket_addr(hostname, stun_socket).await
                };
                res
            }
        })
        .collect::<Vec<_>>();

    let results = join_all_with_semaphore(results.into_iter(), 1).await;

    StunServerTestResult {
        server,
        socket_tests: results,
    }
}

async fn test_socket_addr(
    hostname: &str,
    socket_addr: SocketAddr,
) -> StunSocketTestResult {
    let local_socket = UdpSocket::bind(
        match socket_addr {
            SocketAddr::V4(..) => { "0.0.0.0:0" }
            SocketAddr::V6(..) => { "[::]:0" }
        }
    ).await.unwrap();

    test_socket(hostname, socket_addr, local_socket.local_addr().unwrap(), &local_socket).await
}

async fn test_socket_addr_against_trusted_party(
    hostname: &str,
    socket_addr: SocketAddr,
) -> StunSocketTestResult {
    let local_socket = UdpSocket::bind(
        match socket_addr {
            SocketAddr::V4(..) => { "0.0.0.0:0" }
            SocketAddr::V6(..) => { "[::]:0" }
        }
    ).await.unwrap();

    let trusted_party_addr = tokio::net::lookup_host("stun.l.google.com:19305").await
        .expect("Trusted party hostname must be resolvable")
        .find_map(|resolved_addr| match &socket_addr {
            SocketAddr::V4(_) => match &resolved_addr {
                SocketAddr::V4(_) => Some(resolved_addr),
                SocketAddr::V6(_) => None,
            },
            SocketAddr::V6(_) => match &resolved_addr {
                SocketAddr::V4(_) => None,
                SocketAddr::V6(_) => Some(resolved_addr)
            }
        }).expect("Trusted party must provide IPv4 and v6 connectivity");

    let mut local_socket_mapping = None;
    for _ in 0..3 {
        let mut client = stunclient::StunClient::new(trusted_party_addr);
        let deadline = Duration::from_secs(5);
        client.set_timeout(deadline);
        match client.query_external_address_async(&local_socket).await {
            Ok(addr) => {local_socket_mapping = Some(addr); break},
            Err(_) => continue
        }
    };

    let local_socket_mapping = local_socket_mapping.expect("Trusted party must provide a valid mapping");

    test_socket(hostname, socket_addr, local_socket_mapping, &local_socket).await
}

async fn test_socket(hostname: &str,
                     stun_server_addr: SocketAddr,
                     expected_addr: SocketAddr,
                     local_socket: &UdpSocket,
) -> StunSocketTestResult {
    let mut client = stunclient::StunClient::new(stun_server_addr);
    let deadline = Duration::from_secs(1);
    client.set_timeout(deadline);

    let start = Instant::now();

    let result = client.query_external_address_async(local_socket).await;

    let request_duration = Instant::now() - start;

    return match result {
        Ok(return_addr) => if return_addr.port() == expected_addr.port() {
            debug!("{:<25} -> Socket {:<21} returned a healthy response", hostname, &stun_server_addr);
            StunSocketTestResult {
                socket: stun_server_addr,
                result: StunSocketResponse::HealthyResponse { rtt: request_duration },
            }
        } else {
            debug!("{:<25} -> Socket {:<21} returned an invalid mapping: expected={}, actual={}", hostname, &stun_server_addr, expected_addr, return_addr);
            StunSocketTestResult {
                socket: stun_server_addr,
                result: StunSocketResponse::InvalidMappingResponse { expected: local_socket.local_addr().unwrap(), actual: return_addr, rtt: request_duration },
            }
        },
        Err(err) => {
            if err.to_string() == "Timed out waiting for STUN server reply" {
                debug!("{:<25} -> Socket {:<21} timed out after {:?}", hostname, &stun_server_addr, deadline);
                StunSocketTestResult {
                    socket: stun_server_addr,
                    result: StunSocketResponse::Timeout { deadline },
                }
            } else {
                debug!("{:<25} -> Socket {:<21} returned an unexpected error: {:?}", hostname, &stun_server_addr, err.to_string());
                StunSocketTestResult {
                    socket: stun_server_addr,
                    result: StunSocketResponse::UnexpectedError { err: err.to_string() },
                }
            }
        }
    };
}
