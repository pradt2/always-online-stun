use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};
use stunclient::Error;
use tokio::io;
use tokio::net::{lookup_host};
use crate::candidates::StunCandidate;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CheckError {
    DnsResolutionFailed,
    IncorrectMappingReturned,
    PartialTimeout,
    Timeout,
}

#[derive(Debug)]
pub struct CandidateProfile {
    pub candidate: StunCandidate,
    pub addrs: Vec<SocketAddr>,
    pub rtt_ms: u32,
}

pub async fn check_candidate(candidate: StunCandidate) -> Result<CandidateProfile, CheckError> {
    let addrs = lookup_host(&candidate).await
        .map_err(|err| CheckError::DnsResolutionFailed)?.collect::<Vec<_>>();
    if addrs.len() == 0 { return Err(CheckError::DnsResolutionFailed); }

    let responses = addrs.iter().map(|address| async move {
        let u = tokio::net::UdpSocket::bind(match address {
            SocketAddr::V4(..) => { "0.0.0.0:0" }
            SocketAddr::V6(..) => { "[::]:0" }
        }.parse::<std::net::SocketAddr>().unwrap()).await.unwrap();
        let local_address = u.local_addr().expect("Local address to be available");
        let mut client = stunclient::StunClient::new(*address);
        client.set_timeout(Duration::from_secs(1));
        let time = Instant::now();
        let res = client.query_external_address_async(&u).await;
        match res {
            Ok(mapped_address) => if mapped_address.port() == local_address.port() {
                Ok((mapped_address, time.elapsed()))
            } else {
                Err(CheckError::IncorrectMappingReturned)
            },
            Err(_) => { Err(CheckError::Timeout) }
        }
    }).collect::<Vec<_>>();

    let responses = futures::future::join_all(responses).await;

    let ok_count = responses.iter()
        .filter(|response| { response.is_ok() })
        .count();

    if ok_count == responses.len() {
        let rtt_ms = responses.iter()
            .filter_map(|response| response.as_ref().ok())
            .map(|response| response.1)
            .map(|duration| duration.as_millis() as u32)
            .sum::<u32>() / responses.len() as u32;

        return Ok(CandidateProfile {
            candidate,
            addrs,
            rtt_ms,
        });
    }

    let ip_fails = responses.iter()
        .filter_map(|response| response.err())
        .filter(|err| err == &CheckError::IncorrectMappingReturned)
        .count();

    if ip_fails > 0 {
        return Err(CheckError::IncorrectMappingReturned);
    }

    let timeouts = responses.iter()
        .filter_map(|response| response.err())
        .filter(|err| err == &CheckError::Timeout)
        .count();

    if timeouts < responses.len() {
        return Err(CheckError::PartialTimeout);
    }

    return Err(CheckError::Timeout);
}
