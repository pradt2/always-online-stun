#!/usr/bin/env bash
cd "$(dirname "$0")"
timestamp=$(date --utc)
git checkout master && \
echo "Checked out master" && \
git pull && \
echo "Pulled from master" && \
cargo run && \
echo "Ran the task using Cargo" && \
git add . && \
git commit -m "Check ${timestamp}" && \
git push && \
echo "Pushed the latest version"
