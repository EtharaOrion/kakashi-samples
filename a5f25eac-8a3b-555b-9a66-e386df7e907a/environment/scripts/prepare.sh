#!/bin/bash -eu
# Unpack the snapshot into /src/sqlite3. No repository is created.
#
# A Git object database inside the graded image is recoverable history, which the
# contamination screen rejects, and it was only ever here so the agent could run
# `git diff`. mkpatch.sh takes that diff against a fresh extraction of the pinned
# snapshot instead, so the tree the agent edits carries no .git at all.
set -euo pipefail
SRC_DIR=/src/sqlite3
rm -rf "$SRC_DIR"
mkdir -p /src
# the archive carries its own sqlite3/ root
tar xzf /opt/harness/src.tgz -C /src
echo "prepared $SRC_DIR"
