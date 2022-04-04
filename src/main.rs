use std::io;
use tokio::time::Instant;
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    pretty_env_logger::init_timed();

    let stun_servers = servers::get_stun_servers().await?;
    info!("Loaded {} stun server candidates", stun_servers.len());

    let stun_server_test_results = stun_servers.into_iter()
        .map(|candidate| {
            async move {
                let test_result = stun::test_udp_stun_server(candidate).await;
                test_result
            }
        })
        .collect::<Vec<_>>();

    let timestamp = Instant::now();
    let stun_server_test_results = join_all_with_semaphore(stun_server_test_results.into_iter(), 100).await;

    write_stun_server_summary(&stun_server_test_results);

    ValidHosts::default(&stun_server_test_results).save().await?;
    ValidIpV4s::default(&stun_server_test_results).save().await?;
    ValidIpV6s::default(&stun_server_test_results).save().await?;

    info!("Finished in {:?}", timestamp.elapsed());
    Ok(())
}

fn write_stun_server_summary(results: &Vec<StunServerTestResult>) {
    let mut all_ok = 0;
    let mut dns_unresolved = 0;
    let mut partial_timeout = 0;
    let mut timeout = 0;
    let mut other = 0;
    results.iter().for_each(|server_test_result| {
        if server_test_result.is_healthy() {
            all_ok += 1;
        } else if !server_test_result.is_resolvable() {
            dns_unresolved += 1;
        } else if server_test_result.is_partial_timeout() {
            partial_timeout += 1;
        } else if server_test_result.is_timeout() {
            timeout += 1;
        } else {
            other += 1;
            for socket_test in &server_test_result.socket_tests {
                match &socket_test.result {
                    StunSocketResponse::HealthyResponse { .. } => { info!("Unhealthy host {:>25} -> socket {:>21} returned a healthy response", server_test_result.server.hostname, socket_test.socket) }
                    StunSocketResponse::InvalidMappingResponse { expected, actual, rtt } => { info!("Unhealthy host {:>25} -> socket {:>21} returned an invalid mapping: expected={} actual={}", server_test_result.server.hostname, socket_test.socket, expected, actual) }
                    StunSocketResponse::Timeout { deadline } => { info!("Unhealthy host {:>25} -> socket {:>21} timed out after {:?}", server_test_result.server.hostname, socket_test.socket, deadline) }
                    StunSocketResponse::UnexpectedError { err } => { info!("Unhealthy host {:>25} -> socket {:>21} returned an unexpected error: {}", server_test_result.server.hostname, socket_test.socket, err) }
                }
            }
        }
    });
    info!(
        "Stats -> OK={}, DNS failure={}, p/Timeout={}, Timeout={}, Other={}",
        all_ok, dns_unresolved, partial_timeout, timeout, other
    );
}