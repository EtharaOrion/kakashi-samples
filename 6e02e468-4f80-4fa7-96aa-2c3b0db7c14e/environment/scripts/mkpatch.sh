#!/bin/bash -eu
# Produce the unified diff of the working tree against the pinned snapshot.
#
# This exists so the image does not have to ship a Git object database. History
# absence is a screening requirement: a repository inside the graded environment is
# recoverable history, and the only reason one was ever staged here was to give the
# agent a way to produce a diff. The snapshot is already in the image, pinned by
# digest, so the diff can be taken against a fresh extraction of it instead.
#
# Output is git-apply compatible at -p1, with a/ and b/ prefixes and no timestamps.
# The header rewrite is done in awk rather than sed on purpose: BSD sed does not
# honour \t inside a bracket expression, so a path containing the letter t would be
# truncated and an edit to test/ossfuzz.c would stop matching the immutable-harness
# rule. That failure is silent, which is the worst kind.
set -euo pipefail

SRC_TGZ=${SRC_TGZ:-/opt/harness/src.tgz}
TREE=${1:-/src/sqlite3}
REPO_DIR=$(basename "$TREE")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar xzf "$SRC_TGZ" -C "$tmp"

# -N is deliberately NOT used. Building the library generates thirty-three files in
# the working tree, the configure output and the amalgamation among them, that do not
# exist in the snapshot. With -N every one of those would enter the patch as a new
# file. The repository this replaces never had that problem because those files were
# untracked and `git diff` reports only tracked, modified files. Diffing without -N
# reproduces that behaviour exactly: common files that differ, and nothing else. The
# "Only in" lines diff prints for the rest are dropped below.
#
# diff exits 1 when the trees differ, which is the normal case here.
diff -ru --exclude=.git "$tmp/$REPO_DIR" "$TREE" | awk -v A="$tmp/$REPO_DIR/" -v B="$TREE/" '
  /^Only in /{ next }
  /^--- /   { sub(/\t.*$/, ""); sub("^--- " A, "--- a/"); print; next }
  /^\+\+\+ /{ sub(/\t.*$/, ""); sub("^\\+\\+\\+ " B, "+++ b/"); print; next }
            { print }
' || true
