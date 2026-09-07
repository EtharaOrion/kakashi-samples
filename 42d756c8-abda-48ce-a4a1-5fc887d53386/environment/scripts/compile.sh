#!/usr/bin/env bash
# Build the parsing harness against whatever tree is sitting at /src/rekor.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/src/rekor}"
OUT_DIR="${OUT_DIR:-/out}"

mkdir -p "$OUT_DIR"
cd "$REPO_DIR"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export CGO_ENABLED=0
go build -o "$OUT_DIR/parseharness" ./cmd/parseharness
echo "compile: built /out/parseharness"
