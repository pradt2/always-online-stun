#!/usr/bin/env bash
cd "$(dirname "$0")"
timestamp=$(date --utc)
git checkout master && \
git pull && \
cargo run && \
git add . && \
git commit -m "Check ${timestamp}" && \
git push