#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo fmt --check --manifest-path desktop/Cargo.toml
cargo clippy --locked --manifest-path desktop/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path desktop/Cargo.toml
npm --prefix ui test
npm --prefix ui run build
node --check electron/main.js
node --check electron/preload.js
mkdir -p checks
cargo build --release --locked
python3 smoke.py
python3 tests/integrations.py
python3 tests/demo.py
cargo test --locked --manifest-path agent/Cargo.toml
