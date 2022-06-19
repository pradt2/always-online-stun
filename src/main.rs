use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;
use futures::StreamExt;
use tokio::time::Instant;
use clap::Parser;

use crate::utils::join_all_with_semaphore;
use crate::outputs::{ValidHosts, ValidIpV4s, ValidIpV6s};
use crate::servers::StunServer;
use crate::stun::{StunServerTestResult, StunSocketResponse};

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

mod servers;
mod stun;
mod utils;
mod outputs;
mod geoip;
mod by_threes_check;

#[derive(Parser, Debug)]
/// Bulk tester of STUN servers
struct Cli {
    /// number of concurrently tested servers
    #[clap(short = 'c', long = "concurrency", default_value_t = 64)]
    concurrency: usize,

    /// whether the running machine is behind a NAT
    #[clap(long = "nat", default_value_t = false)]
    is_behind_nat: bool,

    /// file containing \n-separated host:port STUN servers
    #[clap(long = "candidates", parse(from_os_str), default_value_os_t = PathBuf::from("candidates.txt"))]
    candidates_file: PathBuf,

    /// file for valid host:port values
    #[clap(long = "output-hosts", parse(from_os_str), default_value_os_t = PathBuf::from("valid_hosts.txt"))]
    valid_hosts_file: PathBuf,

    /// file for valid ipv4:port values
    #[clap(long = "output-ipv4", parse(from_os_str), default_value_os_t = PathBuf::from("valid_ipv4s.txt"))]
    valid_ipv4_file: PathBuf,

    /// file for valid ipv6:port values
    #[clap(long = "output-ipv6", parse(from_os_str), default_value_os_t = PathBuf::from("valid_ipv6s.txt"))]
    valid_ipv6_file: PathBuf,

    /// API key for the https://ipgeolocation.io service
    #[clap(long = "ipgeolocation-api-key")]
    ipgeo_api_key: String,

    /// file with geoip cache data
    #[clap(long = "geoip-cache", parse(from_os_str), default_value_os_t = PathBuf::from("geoip_cache.txt"))]
    geoip_cache_file: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let cli: Cli = Cli::parse();

    let client = Rc::new(RefCell::new(geoip::CachedIpGeolocationIpClient::default(cli.geoip_cache_file).await?));

    let stun_servers = servers::get_stun_servers(cli.candidates_file).await?;

    let stun_servers_count = stun_servers.len();
    info!("Loaded {} stun server hosts", stun_servers.len());

    let is_behind_nat = cli.is_behind_nat;
    let stun_server_test_results = stun_servers.into_iter()
        .map(|candidate| async move {
            let test_result = stun::test_udp_stun_server(candidate, is_behind_nat).await;
            print_stun_server_status(&test_result);
            test_result
        })
        .collect::<Vec<_>>();

    let timestamp = Instant::now();
    let stun_server_test_results = join_all_with_semaphore(stun_server_test_results.into_iter(), cli.concurrency).await;

    ValidHosts::default(&stun_server_test_results, cli.valid_hosts_file).save().await?;
    ValidIpV4s::default(&stun_server_test_results, cli.valid_ipv4_file).save().await?;
    ValidIpV6s::default(&stun_server_test_results, cli.valid_ipv6_file).save().await?;

    write_stun_server_summary(stun_servers_count, &stun_server_test_results, timestamp.elapsed());

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
