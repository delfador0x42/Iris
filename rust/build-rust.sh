#!/bin/bash
# Build Rust static library for Xcode integration.
# Called from Xcode Build Phases > Run Script.
set -euo pipefail

RUST_DIR="$(cd "$(dirname "$0")" && pwd)"
CRATE_DIR="$RUST_DIR/iris-parsers"
OUT_DIR="${BUILT_PRODUCTS_DIR:-$CRATE_DIR/target/universal}"

cd "$CRATE_DIR"

# Build for arm64 (Apple Silicon)
cargo build --release --target aarch64-apple-darwin

# Copy to output location
mkdir -p "$OUT_DIR"
cp "target/aarch64-apple-darwin/release/libiris_parsers.a" "$OUT_DIR/libiris_parsers.a"

echo "Built libiris_parsers.a -> $OUT_DIR"
