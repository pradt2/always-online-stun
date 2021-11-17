use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};
use stunclient::Error;
use tokio::io;
use tokio::net::{lookup_host};
use crate::candidates::StunCandidate;

#[derive(Debug)]
pub enum CheckError {
    DnsResolutionFailed,
    PartialTimeout,
    Timeout
}

#[derive(Debug)]
pub struct CandidateProfile {
    pub candidate: StunCandidate,
    pub addrs: Vec<SocketAddr>,
    pub rtt_ms: u32
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
        let mut client = stunclient::StunClient::new(*address);
        client.set_timeout(Duration::from_secs(1));
        let time = Instant::now();
        let res = client.query_external_address_async(&u).await;
        (res, time.elapsed())
    }).collect::<Vec<_>>();

    let responses = futures::future::join_all(responses).await;

    let ok_count = responses.iter()
        .filter(|res_tuple| {
            res_tuple.0.is_ok()
        })
        .count();
    let are_all_ok = ok_count == responses.len();
    let are_non_ok = ok_count == 0;
    if !are_all_ok {
        return if are_non_ok {
            Err(CheckError::Timeout)
        } else {
            Err(CheckError::PartialTimeout)
        }
    }

    let rtt_ms = responses.iter()
        .map(|res_tuple| res_tuple.1)
        .map(|duration| duration.as_millis() as u32)
        .sum::<u32>() / responses.len() as u32;

    Ok(CandidateProfile {
        candidate,
        addrs,
        rtt_ms
    })
}