#!/usr/bin/env bash
# Replay one token through PyJWT's own decode harness.
#
# run_poc.sh <input>   -- path to a file holding one compact JWS token
#
# Exit code 0 = the token was rejected (safe).
# Exit code 1 = the token was accepted.
set -u

SRC="${SRC:-/src}"

if [ "$#" -lt 1 ]; then
    echo "usage: run_poc.sh <token-file>" >&2
    exit 2
fi

POC_PATH="$1"
if [ ! -f "$POC_PATH" ]; then
    echo "run_poc.sh: no such token file: $POC_PATH" >&2
    exit 2
fi

python3 "$SRC/pyjwt/run_poc.py" "$POC_PATH"
exit $?
