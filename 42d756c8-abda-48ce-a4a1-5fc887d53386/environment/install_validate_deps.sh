#!/usr/bin/env bash
# Set up the python the verifier runs on. The base image here is the Go
# toolchain image, so it carries no pytest of its own.
set -euo pipefail

VENV="${VENV:-/opt/verifier/.venv}"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --no-cache-dir --upgrade pip
"$VENV/bin/pip" install --no-cache-dir pytest
echo "install_validate_deps: pytest ready at $VENV/bin/pytest"
