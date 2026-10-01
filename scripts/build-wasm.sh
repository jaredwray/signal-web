#!/usr/bin/env bash
# Builds crates/signal-web-core for the browser and writes the wasm-bindgen
# output to web/pkg/. Requirements: the Rust toolchain from rust-toolchain.toml
# (installed automatically by rustup), protoc (SPQR's build script),
# and wasm-bindgen-cli 0.2.129:
#   cargo install wasm-bindgen-cli --version 0.2.129 --locked
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --locked --release --target wasm32-unknown-unknown -p signal-web-core
rm -rf web/pkg
wasm-bindgen --target web --out-dir web/pkg \
  target/wasm32-unknown-unknown/release/signal_web_core.wasm

wasm=web/pkg/signal_web_core_bg.wasm
echo "built $wasm: $(wc -c < "$wasm") bytes raw, $(gzip -9 -c "$wasm" | wc -c) bytes gzip -9"
