use std::collections::HashSet;
use std::thread;
use rand::seq::SliceRandom;
use rand::thread_rng;
use stunclient::Error;
use tokio::{io};
use tokio::macros::support::thread_rng_n;
use tokio::time::Instant;
use tokio_stream::{iter, StreamExt};
use crate::stun::CheckError;

mod candidates;
mod stun;

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let stream = candidates::get_candidates().await?.into_iter();
    let profiles = stream
        .map(|candidate| async move {
            let res = stun::check_candidate(candidate.clone()).await;
            match &res {
                Ok(profile) => { println!("Success: {:?}", profile) }
                Err(err) => { println!("Failure: {:?}", err) }
            }
            res
        })
        .collect::<Vec<_>>();
    let timestamp = Instant::now();
    let profiles = futures::future::join_all(profiles).await;
    let mut all_ok = 0;
    let mut dns_unresolved = 0;
    let mut partial_timeout = 0;
    let mut complete_timeout = 0;
    let mut incorrect_mapping_returned = 0;
    profiles.iter().for_each(|res| {
        match res {
            Ok(_) => { all_ok += 1; }
            Err(CheckError::DnsResolutionFailed) => { dns_unresolved += 1; }
            Err(CheckError::PartialTimeout) => { partial_timeout += 1; }
            Err(CheckError::Timeout) => { complete_timeout += 1; }
            Err(CheckError::IncorrectMappingReturned) => { incorrect_mapping_returned += 1; }
        }
    });
    println!(
        "OK {} , DNS failure {} , p/Timeout {} , Timeout {} , Incorrect {}",
        all_ok, dns_unresolved, partial_timeout, complete_timeout, incorrect_mapping_returned
    );

    let mut output_hosts = profiles.iter()
        .filter_map(|res| res.as_ref().ok())
        .map(|profile| profile.candidate.clone())
        .collect::<Vec<_>>();
    output_hosts.shuffle(&mut thread_rng());
    let output_hosts = output_hosts.into_iter()
        .map(|candidate| String::from(candidate))
        .reduce(|a, b| format!("{}\n{}", a, b))
        .unwrap_or(String::from(""));
    tokio::fs::write("valid_hosts.txt", output_hosts).await?;

    let output_ip4 = profiles.iter()
        .filter_map(|res| res.as_ref().ok())
        .flat_map(|profile| profile.addrs.clone().into_iter())
        .filter(|addr| addr.is_ipv4())
        .map(|addr| addr.to_string())
        .collect::<HashSet<_>>();
    let mut output_ip4 = output_ip4.into_iter()
        .collect::<Vec<_>>();
    output_ip4.shuffle(&mut thread_rng());
    let output_ip4 = output_ip4.into_iter()
        .reduce(|a, b| format!("{}\n{}", a, b))
        .unwrap_or(String::from(""));
    tokio::fs::write("valid_ipv4s.txt", output_ip4).await?;

    let output_ip6 = profiles.iter()
        .filter_map(|res| res.as_ref().ok())
        .flat_map(|profile| profile.addrs.clone().into_iter())
        .filter(|addr| addr.is_ipv6())
        .map(|addr| addr.to_string())
        .collect::<HashSet<_>>();
    let mut output_ip6 = output_ip6.into_iter()
        .collect::<Vec<_>>();
    output_ip6.shuffle(&mut thread_rng());
    let output_ip6 = output_ip6.into_iter()
        .reduce(|a, b| format!("{}\n{}", a, b))
        .unwrap_or(String::from(""));
    tokio::fs::write("valid_ipv6s.txt", output_ip6).await?;

    println!("Finished in {:?}", timestamp.elapsed());
    Ok(())
}
