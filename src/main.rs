use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use futures::StreamExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;
use crate::geoip::GeolocationDbClient;
use crate::utils::join_all_with_semaphore;
use crate::outputs::{ValidHosts, ValidIpV4s, ValidIpV6s};
use crate::servers::StunServer;
use crate::stun::{StunServerTestResult, StunSocketResponse};

extern crate pretty_env_logger;
#[macro_use] extern crate log;

mod servers;
mod stun;
mod utils;
mod outputs;
mod geoip;

const CONCURRENT_SOCKETS_USED_LIMIT: usize = 16;

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();
    test_udp_servers().await;
    test_tcp_servers().await
}

async fn test_udp_servers() -> io::Result<()> {
    let is_behind_nat: bool = std::env::var("IS_BEHIND_NAT")
        .unwrap_or(String::from("false"))
        .parse()
        .expect("IS_BEHIND_NAT must be true or false");

    let ref_socket_addrs = tokio::net::lookup_host("stun.bethesda.net:3478").await;
    if ref_socket_addrs.is_err() {
        error!("Reference STUN error: host not found!");
    }

    let ref_socket_addrs: Vec<_> = ref_socket_addrs.unwrap().collect();

    let ref_socket_addr_v4 = ref_socket_addrs.iter().find_map(|addr| match addr {
        SocketAddr::V4(v4_addr) => Some(v4_addr.clone()),
        SocketAddr::V6(_) => None,
    }).unwrap();

    let deadline = Duration::from_secs(1);
    let local_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    let resV4 = stun::query_stun_server_udp(&local_socket, SocketAddr::from(ref_socket_addr_v4), deadline).await;
    if resV4.is_err() {
        error!("Reference STUN error: failed to obtain reference V4 mapping!")
    }

    let mut resV4 = resV4.unwrap().mapped_addr.unwrap();
    resV4.set_port(0);
    let expected_addr_v4 = if is_behind_nat { Some(resV4) } else { None };

    let ref_socket_addr_v6 = ref_socket_addrs.iter().find_map(|addr| match addr {
        SocketAddr::V4(_) => None,
        SocketAddr::V6(v6_addr) => Some(v6_addr.clone()),
    }).unwrap();

    let deadline = Duration::from_secs(1);
    let local_socket = UdpSocket::bind("[::]:0").await.unwrap();

    let resV6 = stun::query_stun_server_udp(&local_socket, SocketAddr::from(ref_socket_addr_v6), deadline).await;
    if resV6.is_err() {
        error!("Reference STUN error: failed to obtain reference V6 mapping!")
    }

    let mut resV6 = resV6.unwrap().mapped_addr.unwrap();
    resV6.set_port(0);

    let expected_addr_v6 = if is_behind_nat { Some(resV6) } else { None };

    let client = Rc::new(RefCell::new(geoip::CachedIpGeolocationIpClient::<GeolocationDbClient>::default().await?));

    let stun_servers = servers::get_stun_servers().await?;

    let stun_servers_count = stun_servers.len();
    info!("Loaded {} stun server hosts", stun_servers.len());

    let stun_server_test_results = stun_servers.into_iter()
        .map(|candidate| async move {
            let test_result = stun::test_udp_stun_server(candidate, expected_addr_v4, expected_addr_v6).await;
            print_stun_server_status(&test_result);
            test_result
        })
        .collect::<Vec<_>>();

    let timestamp = Instant::now();
    let stun_server_test_results = join_all_with_semaphore(stun_server_test_results.into_iter(), CONCURRENT_SOCKETS_USED_LIMIT).await;

    ValidHosts::udp(&stun_server_test_results).save().await?;
    ValidIpV4s::udp(&stun_server_test_results).save().await?;
    ValidIpV6s::udp(&stun_server_test_results).save().await?;

    ValidHosts::udp_with_nat_testing(&stun_server_test_results).save().await?;
    ValidIpV4s::udp_with_nat_testing(&stun_server_test_results).save().await?;
    ValidIpV6s::udp_with_nat_testing(&stun_server_test_results).save().await?;

    write_stun_server_summary(stun_servers_count, &stun_server_test_results,timestamp.elapsed());

    futures::stream::iter(stun_server_test_results.iter())
        .filter_map(|test_result| async move { if test_result.is_healthy() { Some(test_result) } else { None } })
        .map(|test_result| futures::stream::iter(test_result.socket_tests.iter()))
        .flatten()
        .map(|test_result| test_result.socket)
        .for_each(|socket| {
            let client = client.clone();
            async move {
                // GEO IP data provider no longer exists
                // TODO find a new data provider and point to it
                // client.borrow_mut().get_ip_geoip_info(socket.ip()).await.expect("GeoIP IP info must be available");
            }
        }).await;

    client.borrow_mut().save().await?;

    Ok(())
}

async fn test_tcp_servers() -> io::Result<()> {
    let is_behind_nat: bool = std::env::var("IS_BEHIND_NAT")
        .unwrap_or(String::from("false"))
        .parse()
        .expect("IS_BEHIND_NAT must be true or false");

    let ref_socket_addrs = tokio::net::lookup_host("stun.bethesda.net:3478").await;
    if ref_socket_addrs.is_err() {
        error!("Reference STUN error: host not found!");
    }

    let ref_socket_addrs: Vec<_> = ref_socket_addrs.unwrap().collect();

    let ref_socket_addr_v4 = ref_socket_addrs.iter().find_map(|addr| match addr {
        SocketAddr::V4(v4_addr) => Some(v4_addr.clone()),
        SocketAddr::V6(_) => None,
    }).unwrap();

    let deadline = Duration::from_secs(1);
    let local_socket = tokio::time::timeout(deadline, TcpStream::connect(ref_socket_addr_v4)).await;

    if local_socket.is_err() {
        error!("Reference STUN error: failed to connect V4");
    }

    let mut local_socket = local_socket.unwrap().unwrap();

    let resV4 = stun::query_stun_server_tcp(&mut local_socket, deadline).await;
    if resV4.is_err() {
        error!("Reference STUN error: failed to obtain reference V4 mapping!")
    }

    let mut resV4 = resV4.unwrap().mapped_addr.unwrap();
    resV4.set_port(0);
    let expected_addr_v4 = if is_behind_nat { Some(resV4) } else { None };

    let ref_socket_addr_v6 = ref_socket_addrs.iter().find_map(|addr| match addr {
        SocketAddr::V4(_) => None,
        SocketAddr::V6(v6_addr) => Some(v6_addr.clone()),
    }).unwrap();

    let deadline = Duration::from_secs(1);
    let local_socket = tokio::time::timeout(deadline, TcpStream::connect(ref_socket_addr_v6)).await;

    if local_socket.is_err() {
        error!("Reference STUN error: failed to connect V6");
    }

    let mut local_socket = local_socket.unwrap().unwrap();

    let resV6 = stun::query_stun_server_tcp(&mut local_socket, deadline).await;
    if resV6.is_err() {
        error!("Reference STUN error: failed to obtain reference V6 mapping!")
    }

    let mut resV6 = resV6.unwrap().mapped_addr.unwrap();
    resV6.set_port(0);

    let expected_addr_v6 = if is_behind_nat { Some(resV6) } else { None };

    let client = Rc::new(RefCell::new(geoip::CachedIpGeolocationIpClient::<GeolocationDbClient>::default().await?));

    let stun_servers = servers::get_stun_servers().await?;

    let stun_servers_count = stun_servers.len();
    info!("Loaded {} stun server hosts", stun_servers.len());

    let stun_server_test_results = stun_servers.into_iter()
        .map(|candidate| async move {
            let test_result = stun::test_tcp_stun_server(candidate, expected_addr_v4, expected_addr_v6).await;
            print_stun_server_status(&test_result);
            test_result
        })
        .collect::<Vec<_>>();

    let timestamp = Instant::now();
    let stun_server_test_results = join_all_with_semaphore(stun_server_test_results.into_iter(), CONCURRENT_SOCKETS_USED_LIMIT).await;

    ValidHosts::tcp(&stun_server_test_results).save().await?;
    ValidIpV4s::tcp(&stun_server_test_results).save().await?;
    ValidIpV6s::tcp(&stun_server_test_results).save().await?;

    ValidHosts::tcp_with_nat_testing(&stun_server_test_results).save().await?;
    ValidIpV4s::tcp_with_nat_testing(&stun_server_test_results).save().await?;
    ValidIpV6s::tcp_with_nat_testing(&stun_server_test_results).save().await?;

    write_stun_server_summary(stun_servers_count, &stun_server_test_results,timestamp.elapsed());

    futures::stream::iter(stun_server_test_results.iter())
        .filter_map(|test_result| async move { if test_result.is_healthy() { Some(test_result) } else { None } })
        .map(|test_result| futures::stream::iter(test_result.socket_tests.iter()))
        .flatten()
        .map(|test_result| test_result.socket)
        .for_each(|socket| {
            let client = client.clone();
            async move {
                client.borrow_mut().get_ip_geoip_info(socket.ip()).await.expect("GeoIP IP info must be available");
            }
        }).await;

    client.borrow_mut().save().await?;

    Ok(())
}

fn print_stun_server_status(test_result: &StunServerTestResult) {
    if test_result.is_healthy() {
        info!("{:<25} -> Host is healthy", test_result.server.hostname);
    } else if !test_result.is_resolvable() {
        info!("{:<25} -> Host is not resolvable", test_result.server.hostname);
    } else if test_result.is_partial_timeout() {
        info!("{:<25} -> Host times out on some sockets", test_result.server.hostname);
    } else if test_result.is_timeout() {
        info!("{:<25} -> Host times out on all sockets", test_result.server.hostname);
    } else {
        info!("{:<25} -> Host behaves in an unexpected way. Run with RUST_LOG=DEBUG for more info", test_result.server.hostname);
        for socket_test in &test_result.socket_tests {
            match &socket_test.result {
                StunSocketResponse::HealthyResponse { .. } => { debug!("{:<25} -> Socket {:<21} returned a healthy response", test_result.server.hostname, socket_test.socket) }
                StunSocketResponse::InvalidMappingResponse { expected, actual, .. } => { debug!("{:<25} -> Socket {:<21} returned an invalid mapping: expected={} actual={}", test_result.server.hostname, socket_test.socket, expected, actual) }
                StunSocketResponse::Timeout { deadline } => { debug!("{:<25} -> Socket {:<21} timed out after {:?}", test_result.server.hostname, socket_test.socket, deadline) }
                StunSocketResponse::UnexpectedError { err } => { debug!("{:<25} -> Socket {:<21} returned an unexpected error: {}", test_result.server.hostname, socket_test.socket, err) }
            }
        }
    }
}

fn write_stun_server_summary(candidate_hosts_count: usize, results: &Vec<StunServerTestResult>, time_taken: Duration) {
    let mut healthy = 0;
    let mut dns_unresolved = 0;
    let mut partial_timeout = 0;
    let mut timeout = 0;
    let mut unexpected_err = 0;
    results.iter().for_each(|server_test_result| {
        if server_test_result.is_healthy() {
            healthy += 1;
        } else if !server_test_result.is_resolvable() {
            dns_unresolved += 1;
        } else if server_test_result.is_partial_timeout() {
            partial_timeout += 1;
        } else if server_test_result.is_timeout() {
            timeout += 1;
        } else {
            unexpected_err += 1;
        }
    });
    info!(
        "Statistics -> Tested={}, Healthy={}, DNS failure={}, partial Timeout={}, Timeout={}, Unexpected err={}. Finished in {:?}",
        candidate_hosts_count, healthy, dns_unresolved, partial_timeout, timeout, unexpected_err, time_taken
    );

    if healthy == 0 {
        warn!("No healthy hosts found! Are you behind NAT?")
    }
}
