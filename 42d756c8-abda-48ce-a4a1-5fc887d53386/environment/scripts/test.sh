#!/usr/bin/env bash
# The project's own test suite.
# Stage 3 leans on this to catch a patch that breaks ordinary behaviour.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/src/rekor}"
cd "$REPO_DIR"
export GOFLAGS="${GOFLAGS:--mod=mod}"
export CGO_ENABLED=0
go test ./pkg/types/...
