#!/usr/bin/env bash
# Differential conformance test: the Zig node and the independent Rust reference
# implementation must produce byte-for-byte identical output for the shared
# consensus vectors. Any difference is a consensus divergence.
set -euo pipefail
cd "$(dirname "$0")/.."

rust_out="$(mktemp)"
zig_out="$(mktemp)"
trap 'rm -f "$rust_out" "$zig_out"' EXIT

echo "Building Rust reference implementation..."
( cd refimpl-rs && cargo build --release --quiet )

echo "Building Zig vectors tool..."
zig build >/dev/null

echo "Running both against spec/vectors/scenarios.json..."
./refimpl-rs/target/release/vectors spec/vectors/scenarios.json > "$rust_out"
./zig-out/bin/zigchain-vectors 2> "$zig_out"

if diff -u "$rust_out" "$zig_out"; then
  echo "✅ Zig and Rust agree byte-for-byte ($(wc -l < "$rust_out" | tr -d ' ') report lines)"
else
  echo "❌ CONSENSUS DIVERGENCE between Zig and Rust — investigate immediately"
  exit 1
fi
