#!/usr/bin/env bash
# Copyright 2026 The CVECondor Authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the release binaries into dist/cvecondor-<version>-<target>, with a SHA256SUMS file next to them.
#
# On macOS: aarch64-apple-darwin natively, and the two static Linux (musl) binaries cross-compiled with clang and
# rust-lld, no Docker. `ring` (the TLS crypto) compiles C, so for each musl target the C compiler is clang with
# freestanding flags (there is no musl sysroot on the Mac) and the linker is rust-lld.
# On Linux: the native musl target, built plainly.
#
# Needs rustup (targets are added as required), clang, and on macOS the Xcode command line tools.
# Set CARGO_TARGET_DIR to keep build output out of ./target.
set -euo pipefail

cd "$(dirname "$0")/.."
version="$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)"
dist=dist
mkdir -p "$dist"

target_dir="${CARGO_TARGET_DIR:-target}"

# Builds one target and copies the binary to dist/. Extra environment for cargo comes in as `env` arguments.
build() {
  local target="$1"; shift
  rustup target add "$target"
  env "$@" cargo build --release --locked --target "$target"
  cp "$target_dir/$target/release/cvecondor" "$dist/cvecondor-$version-$target"
  echo "built $dist/cvecondor-$version-$target"
}

# Cross-compiles a musl target from macOS.
build_musl_cross() {
  local target="$1"
  local lower="${target//-/_}"
  local upper
  upper="$(echo "$lower" | tr '[:lower:]' '[:upper:]')"
  build "$target" \
    "CC_$lower=clang" \
    "AR_$lower=ar" \
    "CFLAGS_$lower=-ffreestanding -U__musl__ -DRING_CORE_NOSTDLIBINC=1" \
    "CARGO_TARGET_${upper}_LINKER=rust-lld"
}

case "$(uname -s)" in
  Darwin)
    build aarch64-apple-darwin
    build_musl_cross x86_64-unknown-linux-musl
    build_musl_cross aarch64-unknown-linux-musl
    ;;
  Linux)
    build "$(uname -m)-unknown-linux-musl"
    ;;
  *)
    echo "release.sh: unsupported OS $(uname -s)" >&2
    exit 1
    ;;
esac

cd "$dist"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "cvecondor-$version-"* > SHA256SUMS
else
  shasum -a 256 "cvecondor-$version-"* > SHA256SUMS
fi
cat SHA256SUMS
