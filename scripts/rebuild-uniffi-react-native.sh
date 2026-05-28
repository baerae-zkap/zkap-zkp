#!/usr/bin/env bash
# Rebuild UniFFI React Native bindings and bundled mobile native libraries.
#
# Usage:
#   bash scripts/rebuild-uniffi-react-native.sh
#   SKIP_ANDROID=1 bash scripts/rebuild-uniffi-react-native.sh
#   SKIP_IOS=1 bash scripts/rebuild-uniffi-react-native.sh
#
# Environment:
#   ANDROID_NDK_HOME / NDK_HOME / ANDROID_SDK_ROOT / ANDROID_HOME
#     Used to locate the Android NDK.
#   ANDROID_TARGETS
#     Space-separated Rust Android targets. Defaults to the targets in
#     packages/sdk-react-native/ubrn.config.yaml:
#       "aarch64-linux-android x86_64-linux-android"
#   SKIP_ANDROID=1
#     Skip Android .so rebuild.
#   SKIP_IOS=1
#     Skip iOS XCFramework rebuild.
#   SKIP_TYPECHECK=1
#     Skip sdk-react-native TypeScript typecheck.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RN_PACKAGE_DIR="$REPO_ROOT/packages/sdk-react-native"

ANDROID_TARGETS="${ANDROID_TARGETS:-aarch64-linux-android x86_64-linux-android}"
SKIP_ANDROID="${SKIP_ANDROID:-0}"
SKIP_IOS="${SKIP_IOS:-0}"
SKIP_TYPECHECK="${SKIP_TYPECHECK:-0}"

usage() {
  cat <<'EOF'
Rebuild UniFFI React Native bindings and bundled mobile native libraries.

Usage:
  bash scripts/rebuild-uniffi-react-native.sh
  SKIP_ANDROID=1 bash scripts/rebuild-uniffi-react-native.sh
  SKIP_IOS=1 bash scripts/rebuild-uniffi-react-native.sh

Environment:
  ANDROID_NDK_HOME / NDK_HOME / ANDROID_SDK_ROOT / ANDROID_HOME
    Used to locate the Android NDK.
  ANDROID_TARGETS
    Space-separated Rust Android targets. Defaults to the targets in
    packages/sdk-react-native/ubrn.config.yaml:
      "aarch64-linux-android x86_64-linux-android"
  SKIP_ANDROID=1
    Skip Android .so rebuild.
  SKIP_IOS=1
    Skip iOS XCFramework rebuild.
  SKIP_TYPECHECK=1
    Skip sdk-react-native TypeScript typecheck.
EOF
}

step() {
  printf '\n==> %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

debug_lib_path() {
  case "$(uname -s)" in
    Darwin) printf '%s\n' "$REPO_ROOT/target/debug/libzkap_uniffi_bindings.dylib" ;;
    Linux) printf '%s\n' "$REPO_ROOT/target/debug/libzkap_uniffi_bindings.so" ;;
    *)
      echo "ERROR: unsupported host OS for UniFFI debug library: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

android_abi_for_target() {
  case "$1" in
    aarch64-linux-android) printf '%s\n' "arm64-v8a" ;;
    armv7-linux-androideabi) printf '%s\n' "armeabi-v7a" ;;
    x86_64-linux-android) printf '%s\n' "x86_64" ;;
    i686-linux-android) printf '%s\n' "x86" ;;
    *)
      echo "ERROR: unsupported Android target: $1" >&2
      exit 1
      ;;
  esac
}

android_linker_for_target() {
  case "$1" in
    aarch64-linux-android) printf '%s\n' "aarch64-linux-android21-clang" ;;
    armv7-linux-androideabi) printf '%s\n' "armv7a-linux-androideabi21-clang" ;;
    x86_64-linux-android) printf '%s\n' "x86_64-linux-android21-clang" ;;
    i686-linux-android) printf '%s\n' "i686-linux-android21-clang" ;;
    *)
      echo "ERROR: unsupported Android target: $1" >&2
      exit 1
      ;;
  esac
}

find_android_ndk() {
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${NDK_HOME:-}"; do
    if [ -n "$candidate" ] && [ -d "$candidate/toolchains/llvm/prebuilt" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  local sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
  if [ -d "$sdk_root/ndk" ]; then
    candidate="$(find "$sdk_root/ndk" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -1)"
    if [ -n "$candidate" ] && [ -d "$candidate/toolchains/llvm/prebuilt" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi

  echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or ANDROID_SDK_ROOT." >&2
  exit 1
}

find_android_toolchain_bin() {
  local ndk="$1"
  local pattern
  case "$(uname -s)" in
    Darwin) pattern='darwin-*' ;;
    Linux) pattern='linux-*' ;;
    *)
      echo "ERROR: unsupported host OS for Android NDK: $(uname -s)" >&2
      exit 1
      ;;
  esac

  local prebuilt_dir
  prebuilt_dir="$(find "$ndk/toolchains/llvm/prebuilt" -maxdepth 1 -mindepth 1 -type d -name "$pattern" | sort | head -1)"
  if [ -z "$prebuilt_dir" ] || [ ! -d "$prebuilt_dir/bin" ]; then
    echo "ERROR: Android NDK toolchain not found under $ndk/toolchains/llvm/prebuilt" >&2
    exit 1
  fi

  printf '%s\n' "$prebuilt_dir/bin"
}

build_android_target() {
  local target="$1"
  local ndk="$2"
  local toolchain_bin="$3"
  local abi linker target_env cc_suffix out_dir

  abi="$(android_abi_for_target "$target")"
  linker="$toolchain_bin/$(android_linker_for_target "$target")"
  target_env="$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')"
  cc_suffix="$(printf '%s' "$target" | tr '-' '_')"
  out_dir="$RN_PACKAGE_DIR/android/libs/$abi"

  if [ ! -x "$linker" ]; then
    echo "ERROR: Android linker not executable: $linker" >&2
    exit 1
  fi

  step "Build Android $abi ($target)"
  env \
    "ANDROID_NDK_HOME=$ndk" \
    "CARGO_TARGET_${target_env}_LINKER=$linker" \
    "CC_${cc_suffix}=$linker" \
    "AR_${cc_suffix}=$toolchain_bin/llvm-ar" \
    cargo build --release --target "$target" -p zkap-uniffi-bindings

  mkdir -p "$out_dir"
  cp "$REPO_ROOT/target/$target/release/libzkap_uniffi_bindings.so" \
    "$out_dir/libzkap_uniffi_bindings.so"
  ls -lh "$out_dir/libzkap_uniffi_bindings.so"
}

cd "$REPO_ROOT"

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    echo "ERROR: unknown argument: $1" >&2
    usage >&2
    exit 2
    ;;
esac

require_cmd cargo
require_cmd npx

step "Build debug UniFFI library for JSI binding generation"
cargo build -p zkap-uniffi-bindings

DEBUG_LIB="$(debug_lib_path)"
if [ ! -f "$DEBUG_LIB" ]; then
  echo "ERROR: expected debug UniFFI library missing: $DEBUG_LIB" >&2
  exit 1
fi

step "Regenerate React Native UniFFI JSI bindings"
npx uniffi-bindgen-react-native generate jsi bindings \
  --library \
  --crate zkap_uniffi_bindings \
  --ts-dir packages/sdk-react-native/src/generated \
  --cpp-dir packages/sdk-react-native/cpp/generated \
  "$DEBUG_LIB"

if [ "$SKIP_TYPECHECK" != "1" ]; then
  step "Typecheck sdk-react-native"
  (cd "$RN_PACKAGE_DIR" && npm run typecheck)
fi

if [ "$SKIP_ANDROID" != "1" ]; then
  NDK="$(find_android_ndk)"
  TOOLCHAIN_BIN="$(find_android_toolchain_bin "$NDK")"
  for target in $ANDROID_TARGETS; do
    build_android_target "$target" "$NDK" "$TOOLCHAIN_BIN"
  done
else
  step "Skip Android rebuild"
fi

if [ "$SKIP_IOS" != "1" ]; then
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "ERROR: iOS XCFramework rebuild requires macOS. Set SKIP_IOS=1 to skip." >&2
    exit 1
  fi
  require_cmd xcodebuild
  require_cmd lipo
  step "Build iOS XCFramework"
  bash "$REPO_ROOT/scripts/build-ios-xcframework.sh"
else
  step "Skip iOS rebuild"
fi

step "Done"
git status --short -- packages/sdk-react-native
