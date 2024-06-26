use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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

    pub(crate) fn is_nat_testing_supported(&self) -> bool {
        self.socket_tests.iter()
            .all(StunSocketTestResult::is_nat_testing_supported)
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

    pub(crate) fn is_nat_testing_supported(&self) -> bool {
        self.result.is_nat_testing_supported()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum StunSocketResponse {
    HealthyResponse { rtt: Duration, supports_nat_testing: bool },
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

    fn is_nat_testing_supported(&self) -> bool {
        match &self {
            StunSocketResponse::HealthyResponse { supports_nat_testing: true, .. } => true,
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
                    test_socket_addr_against_trusted_party_udp(hostname, stun_socket).await
                } else {
                    test_socket_addr_udp(hostname, stun_socket).await
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

pub(crate) async fn test_tcp_stun_server(
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
                    test_socket_addr_against_trusted_party_tcp(hostname, stun_socket).await
                } else {
                    test_socket_addr_tcp(hostname, stun_socket).await
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

async fn test_socket_addr_udp(
    hostname: &str,
    socket_addr: SocketAddr,
) -> StunSocketTestResult {
    let local_socket = UdpSocket::bind(
        match socket_addr {
            SocketAddr::V4(..) => { "0.0.0.0:0" }
            SocketAddr::V6(..) => { "[::]:0" }
        }
    ).await.unwrap();

    test_socket_udp(hostname, socket_addr, local_socket.local_addr().unwrap(), &local_socket).await
}

async fn test_socket_addr_tcp(
    hostname: &str,
    socket_addr: SocketAddr,
) -> StunSocketTestResult {
    let deadline = Duration::from_secs(1);
    let local_socket = tokio::time::timeout(deadline, TcpStream::connect(socket_addr)).await;

    match local_socket {
        Ok(Ok(stream)) => test_socket_tcp(hostname, stream).await,
        Ok(Err(err)) => return StunSocketTestResult {
            socket: socket_addr,
            result: StunSocketResponse::UnexpectedError { err: err.to_string() }
        },
        Err(err) => return StunSocketTestResult {
            socket: socket_addr,
            result: StunSocketResponse::UnexpectedError { err: err.to_string() }
        }
    }

}

async fn test_socket_addr_against_trusted_party_udp(
    hostname: &str,
    socket_addr: SocketAddr,
) -> StunSocketTestResult {
    let local_socket = UdpSocket::bind(
        match socket_addr {
            SocketAddr::V4(..) => { "0.0.0.0:0" }
            SocketAddr::V6(..) => { "[::]:0" }
        }
    ).await.unwrap();

    let trusted_party_addr = tokio::net::lookup_host("stun1.l.google.com:19302").await
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
        }).expect("Trusted party must provide IP v4 and v6 connectivity");

    let mut local_socket_mapping = None;
    for _ in 0..3 {
        match query_stun_server_udp(&local_socket, trusted_party_addr, Duration::from_secs(5)).await.ok() {
            Some(QueryStunServerResult{mapped_addr: Some(mapped_addr), ..}) => {local_socket_mapping = Some(mapped_addr); break},
            _ => continue
        }
    };

    let local_socket_mapping = local_socket_mapping.expect("Trusted party must provide a valid mapping");

    test_socket_udp(hostname, socket_addr, local_socket_mapping, &local_socket).await
}

/**
    Until I figure out the SO_REUSEADDR,
    Any returned address is regarded as valid
*/
async fn test_socket_addr_against_trusted_party_tcp(
    hostname: &str,
    socket_addr: SocketAddr,
) -> StunSocketTestResult {
    let start = Instant::now();
    let deadline = Duration::from_secs(1);

    let local_socket = tokio::time::timeout(deadline, TcpStream::connect(socket_addr)).await;

    let mut stream = match local_socket {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return StunSocketTestResult {
            socket: socket_addr,
            result: StunSocketResponse::UnexpectedError { err: err.to_string() }
        },
        Err(err) => return StunSocketTestResult {
            socket: socket_addr,
            result: StunSocketResponse::UnexpectedError { err: err.to_string() }
        }
    };

    let result = query_stun_server_tcp(&mut stream, deadline).await;

    let request_duration = Instant::now() - start;

    if let Ok(QueryStunServerResult{mapped_addr: Some(mapped_addr), ..}) = result {
        process_result(
            result,
            request_duration,
            hostname,
            stream.local_addr().unwrap(),
            mapped_addr,
            stream.peer_addr().ok(),
            deadline,
        )
    } else {
        process_result(
            result,
            request_duration,
            hostname,
            stream.local_addr().unwrap(),
            stream.peer_addr().unwrap_or(std::net::SocketAddr::new(IpAddr::from([0; 4]), 0)), // doesn't matter since the STUN server didn't return a valid address
            stream.peer_addr().ok(),
            deadline,
        )
    }
}

async fn test_socket_udp(hostname: &str,
                         stun_server_addr: SocketAddr,
                         expected_addr: SocketAddr,
                         local_socket: &UdpSocket,
) -> StunSocketTestResult {
    let deadline = Duration::from_secs(1);

    let start = Instant::now();

    let result = query_stun_server_udp(&local_socket, stun_server_addr, deadline).await;

    let request_duration = Instant::now() - start;

    process_result(
        result,
        request_duration,
        hostname,
        local_socket.local_addr().unwrap(),
        expected_addr,
        Some(stun_server_addr),
        deadline,
    )
}

async fn test_socket_tcp(hostname: &str,
                         mut stream: TcpStream,
) -> StunSocketTestResult {
    let deadline = Duration::from_secs(1);

    let start = Instant::now();

    let result = query_stun_server_tcp(&mut stream,deadline).await;

    let request_duration = Instant::now() - start;


    process_result(
        result,
        request_duration,
        hostname,
        stream.local_addr().unwrap(),
        stream.local_addr().unwrap(),
        stream.peer_addr().ok(),
        deadline,
    )
}

fn process_result(
    result: io::Result<QueryStunServerResult>,
    request_duration: Duration,
    hostname: &str,
    local_addr: SocketAddr,
    expected_addr: SocketAddr,
    stun_server_addr: Option<SocketAddr>,
    deadline: Duration,
) -> StunSocketTestResult {
    let stun_server_addr = stun_server_addr.unwrap_or(SocketAddr::new(IpAddr::from([0,0,0,0]), 0));

    return match result {
        Ok(QueryStunServerResult{mapped_addr: Some(mapped_addr), other_addr}) => if mapped_addr.port() == expected_addr.port() {
            debug!("{:<25} -> Socket {:<21} returned a healthy response", hostname, &stun_server_addr);
            // other address cannot be the same as the IP address we're already using for the query
            let is_valid_other_addr = other_addr.map(|arg0: SocketAddr| SocketAddr::ip(&arg0)).map(|ip| ip != mapped_addr.ip()).unwrap_or(false);
            StunSocketTestResult {
                socket: stun_server_addr,
                result: StunSocketResponse::HealthyResponse { rtt: request_duration, supports_nat_testing: is_valid_other_addr },
            }
        } else {
            debug!("{:<25} -> Socket {:<21} returned an invalid mapping: expected={}, actual={}", hostname, &stun_server_addr, expected_addr, mapped_addr);
            StunSocketTestResult {
                socket: stun_server_addr,
                result: StunSocketResponse::InvalidMappingResponse { expected: local_addr, actual: mapped_addr, rtt: request_duration },
            }
        },
        Ok(QueryStunServerResult{mapped_addr: None, other_addr: _}) => {
            debug!("{:<25} -> Socket {:<21} returned an a response but no mapping: expected={}", hostname, &stun_server_addr, expected_addr);
            StunSocketTestResult {
                socket: stun_server_addr,
                result: StunSocketResponse::InvalidMappingResponse { expected: local_addr, actual: SocketAddr::new(IpAddr::from([0,0,0,0]), 0), rtt: request_duration },
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

struct QueryStunServerResult {
    mapped_addr: Option<SocketAddr>,    // address of the client as determined by the STUN server
    other_addr: Option<SocketAddr>,     // the OTHER-ADDRESS reported by the STUN server if the server supports NAT testing
}

async fn query_stun_server_udp(
    local_socket: &UdpSocket,
    server_addr: SocketAddr,
    timeout: Duration,
) -> io::Result<QueryStunServerResult> {
    let mut buf = [0u8; 256];

    let mut msg = stun_format::MsgBuilder::from(buf.as_mut_slice());
    msg.typ(stun_format::MsgType::BindingRequest);
    msg.tid(1);

    local_socket.send_to(msg.as_bytes(), server_addr).await?;

    let bytes_read = tokio::time::timeout(timeout, local_socket.recv(&mut buf)).await??;

    let msg = stun_format::Msg::from(&buf[0..bytes_read]);

    debug!("{:?}", msg);

    let mapped_addr = if let Some(stun_format::MsgType::BindingResponse) = msg.typ() {
        let addr = msg.attrs_iter()
            .map(|attr| {
                match attr {
                    stun_format::Attr::MappedAddress(addr) => Some(addr),
                    stun_format::Attr::XorMappedAddress(addr) => Some(addr),
                    _ => None,
                }
            })
            .filter(|opt| opt.is_some())
            .map(|opt| opt.unwrap())
            .map(|external_addr| match external_addr {
                stun_format::SocketAddr::V4(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                },
                stun_format::SocketAddr::V6(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                }
            })
            .next();

        addr
    } else {
        None
    };

    let other_addr = if let Some(stun_format::MsgType::BindingResponse) = msg.typ() {
        let addr = msg.attrs_iter()
            .map(|attr| {
                match attr {
                    stun_format::Attr::OtherAddress(addr) => Some(addr),
                    _ => None,
                }
            })
            .filter(|opt| opt.is_some())
            .map(|opt| opt.unwrap())
            .map(|external_addr| match external_addr {
                stun_format::SocketAddr::V4(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                },
                stun_format::SocketAddr::V6(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                }
            })
            .next();

        addr
    } else {
        None
    };

    return Ok(QueryStunServerResult{ mapped_addr, other_addr });
}

async fn query_stun_server_tcp(
    local_socket: &mut TcpStream,
    timeout: Duration,
) -> io::Result<QueryStunServerResult> {
    let mut buf = [0u8; 256];

    let mut msg = stun_format::MsgBuilder::from(buf.as_mut_slice());
    msg.typ(stun_format::MsgType::BindingRequest);
    msg.tid(1);

    tokio::time::timeout(timeout, local_socket.write_all(msg.as_bytes())).await??;

    let bytes_read = tokio::time::timeout(timeout, local_socket.read(&mut buf)).await??;

    let msg = stun_format::Msg::from(&buf[0..bytes_read]);

    let mapped_addr = if let Some(stun_format::MsgType::BindingResponse) = msg.typ() {
        let addr = msg.attrs_iter()
            .map(|attr| {
                match attr {
                    stun_format::Attr::MappedAddress(addr) => Some(addr),
                    stun_format::Attr::XorMappedAddress(addr) => Some(addr),
                    _ => None,
                }
            })
            .filter(|opt| opt.is_some())
            .map(|opt| opt.unwrap())
            .map(|external_addr| match external_addr {
                stun_format::SocketAddr::V4(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                },
                stun_format::SocketAddr::V6(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                }
            })
            .next();

        addr
    } else {
        None
    };

    let other_addr = if let Some(stun_format::MsgType::BindingResponse) = msg.typ() {
        let addr = msg.attrs_iter()
            .map(|attr| {
                match attr {
                    stun_format::Attr::OtherAddress(addr) => Some(addr),
                    _ => None,
                }
            })
            .filter(|opt| opt.is_some())
            .map(|opt| opt.unwrap())
            .map(|external_addr| match external_addr {
                stun_format::SocketAddr::V4(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                },
                stun_format::SocketAddr::V6(ip, port) => {
                    SocketAddr::new(std::net::IpAddr::from(ip), port)
                }
            })
            .next();

        addr
    } else {
        None
    };

    return Ok(QueryStunServerResult{ mapped_addr, other_addr });
}
