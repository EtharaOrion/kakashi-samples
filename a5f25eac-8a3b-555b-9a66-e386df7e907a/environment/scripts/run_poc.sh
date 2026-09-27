#!/bin/bash -eu
# Run one input against a staged build and print the verdict record.
#
#   run_poc.sh <variant> [input]
#
# The staged directory is the one compile.sh wrote for that variant, holding the
# ossfuzz entry point this script drives.
set -euo pipefail
VARIANT="${1:-vulnerable}"
INPUT="${2:-/root/workspace/poc.bin}"
OUT_ROOT=/out
OUT_DIR="$OUT_ROOT/$VARIANT"
exec python3 /opt/harness/validate.py \
    --target "$OUT_DIR/ossfuzz" --input "$INPUT"
