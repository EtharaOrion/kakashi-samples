#!/usr/bin/env bash
# prepare.sh for pyjwt.
#
# Nothing to do: the source snapshot is already extracted at $SRC/pyjwt
# and every build dependency is baked into the image, matching the other
# tasks in this batch, so there is a single stable entry point if this task
# ever needs pre-build setup.
set -eu
echo "prepare: source at ${SRC:-/src}/pyjwt, nothing to do"
