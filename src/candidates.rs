use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;
use std::str::FromStr;
use tokio::io;
use tokio_stream::StreamExt;

pub type StunCandidate = String;
const FILE_PATH: &str = "candidates.txt";

pub async fn clean_candidates() -> io::Result<()> {
    let candidates = get_candidates().await?;
    println!("Loaded candidates: {}", candidates.len());
    let mut candidates = remove_duplicates(candidates);
    candidates.sort();
    println!("Unique candidates: {}", candidates.len());
    let s = candidates.into_iter()
        .map(|candidate| candidate.to_string())
        .reduce(|a, b| format!("{}\n{}", a, b))
        .unwrap_or(String::from(""));
    tokio::fs::write(FILE_PATH, s).await
}

pub async fn get_candidates() -> io::Result<Vec<StunCandidate>> {
    Ok(tokio::fs::read_to_string(FILE_PATH).await?
        .split('\n')
        .map(|s| s.trim())
        .filter(|s| !s.starts_with('#'))
        .map(String::from)
        .collect::<Vec<_>>())
}

fn remove_duplicates(candidates: Vec<StunCandidate>) -> Vec<StunCandidate> {
    let mut set = HashSet::with_capacity(candidates.len());
    candidates.into_iter().for_each(|candidate| {
        set.insert(candidate);
    });
    set.into_iter().collect()
}