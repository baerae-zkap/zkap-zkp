#!/usr/bin/env bash
# Build iOS XCFramework for sdk-react-native locally.
# Prerequisites:
#   - macOS with Xcode installed
#   - Rust targets: rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   - Run from the repository root

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INCLUDE_DIR="$REPO_ROOT/packages/sdk-react-native/ios/include"
OUT_DIR="$REPO_ROOT/packages/sdk-react-native/ios/ZkapZkp.xcframework"

echo "==> Building iOS targets..."
cargo build --release --target aarch64-apple-ios      -p zkap-uniffi-bindings
cargo build --release --target aarch64-apple-ios-sim  -p zkap-uniffi-bindings
cargo build --release --target x86_64-apple-ios       -p zkap-uniffi-bindings

echo "==> Creating fat simulator library (arm64 + x86_64)..."
lipo -create \
  "$REPO_ROOT/target/aarch64-apple-ios-sim/release/libzkap_uniffi_bindings.a" \
  "$REPO_ROOT/target/x86_64-apple-ios/release/libzkap_uniffi_bindings.a" \
  -output "$REPO_ROOT/target/libzkap_uniffi_bindings_sim.a"

echo "==> Creating XCFramework..."
rm -rf "$OUT_DIR"
xcodebuild -create-xcframework \
  -library "$REPO_ROOT/target/aarch64-apple-ios/release/libzkap_uniffi_bindings.a" \
  -headers "$INCLUDE_DIR" \
  -library "$REPO_ROOT/target/libzkap_uniffi_bindings_sim.a" \
  -headers "$INCLUDE_DIR" \
  -output "$OUT_DIR"

echo "XCFramework created at $OUT_DIR"
