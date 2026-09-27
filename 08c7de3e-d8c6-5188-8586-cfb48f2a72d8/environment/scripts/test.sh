#!/usr/bin/env bash
# Regression check for the agent's edit.
#
# Runs the project's own pytest suite. A repaired build must still pass it, so
# whatever the repair adds has left the library's existing behaviour intact.
#
# This script asserts nothing about the defect itself, deliberately: run_poc.sh
# is the signal for that, and a regression suite spelling out the behaviour
# expected after the repair would hand over the answer.
set -eu

SRC="${SRC:-/src}"
REPO="$SRC/pyjwt"

cd "$REPO"
echo "=== pyjwt regression: project test suite ==="
python3 -m pytest -q tests/
echo "regression: project test suite passed"
