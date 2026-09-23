#!/usr/bin/env bash
# Lay down a pristine copy of the source tree at /src/rekor.
# Safe to re-run: the old tree is dropped first, so one graded stage
# cannot leak state into the next.
set -euo pipefail

SRC_DIR="${SRC_DIR:-/src}"
REPO_DIR="${REPO_DIR:-$SRC_DIR/rekor}"
TARBALL="${TARBALL:-/tmp/src.tgz}"

if [ ! -f "$TARBALL" ]; then
  echo "prepare: no source tarball at $TARBALL" >&2
  exit 2
fi

rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR"
tar xzf "$TARBALL" -C "$REPO_DIR" --strip-components=0

# Some archives carry a single top level dir. Flatten that away so the repo
# root always sits at $REPO_DIR.
if [ ! -f "$REPO_DIR/go.mod" ]; then
  inner="$(find "$REPO_DIR" -maxdepth 2 -name go.mod -printf '%h\n' | head -1)"
  if [ -n "$inner" ] && [ "$inner" != "$REPO_DIR" ]; then
    shopt -s dotglob
    mv "$inner"/* "$REPO_DIR"/
    shopt -u dotglob
  fi
fi

test -f "$REPO_DIR/go.mod" || { echo "prepare: go.mod missing under $REPO_DIR" >&2; exit 2; }
echo "prepare: source ready at $REPO_DIR"
