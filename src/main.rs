use std::cell::RefCell;
use std::convert::TryInto;
use std::fmt::format;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;
use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use crate::utils::join_all_with_semaphore;
use crate::outputs::{ValidHosts, ValidIpV4s, ValidIpV6s};
use crate::servers::StunServer;
use crate::stun::{StunServerTestResult, StunSocketResponse};
// use crate::stun_codec::{Attribute, NonParsableAttribute};

extern crate pretty_env_logger;
#[macro_use] extern crate log;

mod servers;
mod stun;
mod utils;
mod outputs;
mod geoip;
mod git;

const CONCURRENT_SOCKETS_USED_LIMIT: usize = 64;

async fn get_stun_response(addr: &str) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;
    let cookie =  0x2112A442_u32.to_be_bytes();
    let req = [0, 1u8.to_be(), 0, 0, cookie[0], cookie[1], cookie[2], cookie[3], 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 ];
    sock.send(&req).await?;

    let mut buf = [0u8; 120];
    let bytes_read = tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await?;

    if bytes_read.is_err() {
        info!("Addr {} timed out", addr);
        return Ok(());
    }

    let bytes_read = bytes_read.unwrap();

    // let r = stun_codec::StunMessageReader { bytes: buf[0..bytes_read].as_ref() };
    // info!("Method {:?} , Class {:?}", r.get_method().unwrap(), r.get_class());
    // r.get_attrs().for_each(|attr| {
    //     match &attr {
    //         Ok(attr) => {
    //             match attr {
    //                 Attribute::MappedAddress(r) => info!("MappedAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::ResponseAddress(r) => info!("ResponseAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::ChangeAddress(r) => info!("ChangeAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::SourceAddress(r) => info!("SourceAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::ChangedAddress(r) => info!("ChangedAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::XorMappedAddress(r) => info!("XorMappedAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::OptXorMappedAddress(r) => info!("OptXorMappedAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::OtherAddress(r) => info!("OtherAddress {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::ResponseOrigin(r) => info!("ResponseOrigin {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::AlternateServer(r) => info!("AlternateServer {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::Software(r) => info!("Software {}", r.get_software().unwrap()),
    //                 Attribute::ReflectedFrom(r) => info!("ReflectedFrom {:?}", SocketAddr::new(r.get_address().unwrap(), r.get_port())),
    //                 Attribute::ErrorCode(r) => info!("ErrorCode {:?}", r.get_error().unwrap()),
    //                 Attribute::Fingerprint(r) => info!("Fingerprint {}", r.get_checksum()),
    //                 Attribute::MessageIntegrity(r) => info!("MessageIntegrity {:?}", r.get_digest()),
    //                 Attribute::Realm(r) => info!("Realm {}", r.get_realm().unwrap()),
    //                 Attribute::Nonce(r) => info!("Nonce {}", r.get_nonce().unwrap()),
    //                 Attribute::Password(r) => info!("Password {}", r.get_password().unwrap()),
    //                 Attribute::UnknownAttributes(r) => {
    //                     for attr_code in r.get_attr_codes() {
    //                         info!("Unknown attribute {}", attr_code)
    //                     }
    //                 },
    //                 Attribute::Username(r) => info!("Username {}", r.get_username().unwrap()),
    //             }
    //         }
    //         Err(attr) => {
    //             match &attr {
    //                 NonParsableAttribute::Unknown(r) => warn!("UnknownAttr type {:04x} len {}", r.get_type_raw(), r.get_total_length()),
    //                 NonParsableAttribute::Malformed(r) => warn!("MalformedAttr type {:04x} len {}", r.get_type_raw(), r.get_value_length_raw()),
    //             }
    //         }
    //     }
    // });
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let client = Rc::new(RefCell::new(geoip::CachedIpGeolocationIpClient::default().await?));

    let stun_servers = servers::get_stun_servers().await?;

    let stun_servers_count = stun_servers.len();
    info!("Loaded {} stun server hosts", stun_servers.len());

    let f = stun_servers.iter().map(|server| {
        async move {
            let addr = format!("{}:{}", server.hostname, server.port);
            get_stun_response(addr.as_str()).await;
        }
    }).collect::<Vec<_>>();
    join_all_with_semaphore(f.into_iter(), 1).await;

    let stun_server_test_results = stun_servers.into_iter()
        .map(|candidate| {
            async move {
                let test_result = stun::test_udp_stun_server(candidate).await;
                print_stun_server_status(&test_result);
                test_result
            }
        })
        .collect::<Vec<_>>();

    let timestamp = Instant::now();
    let stun_server_test_results = join_all_with_semaphore(stun_server_test_results.into_iter(), CONCURRENT_SOCKETS_USED_LIMIT).await;

    ValidHosts::default(&stun_server_test_results).save().await?;
    ValidIpV4s::default(&stun_server_test_results).save().await?;
    ValidIpV6s::default(&stun_server_test_results).save().await?;

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
                StunSocketResponse::InvalidMappingResponse { expected, actual, rtt } => { debug!("{:<25} -> Socket {:<21} returned an invalid mapping: expected={} actual={}", test_result.server.hostname, socket_test.socket, expected, actual) }
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
