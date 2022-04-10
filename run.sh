#!/usr/bin/env bash
cd "$(dirname "$0")"
timestamp=$(date --utc)
git checkout master && \
git pull && \
RUST_LOG=info cargo run && \
git add . && \
git commit -m "Check ${timestamp}" && \
git push
