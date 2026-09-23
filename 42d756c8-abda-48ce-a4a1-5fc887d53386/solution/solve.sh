#!/bin/bash
# Reference solution. Harbor's oracle agent uploads this directory to
# /solution and runs this script; the verifier grades /output/poc.bin and
# /output/fix.patch, so the reference answer is to publish both.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p /output
cp "$HERE/poc.bin"   /output/poc.bin
cp "$HERE/fix.patch" /output/fix.patch

echo "published /output/poc.bin and /output/fix.patch"
