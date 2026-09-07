#!/usr/bin/env bash
# pyjwt is already installed editable at image build time, so a source edit
# takes effect on the next import with no reinstall needed. This confirms
# the (possibly just-edited) source has no syntax error and the module
# graph still resolves before a replay or regression run, the same role
# compile.sh plays for a compiled project. No network reach: re-running
# `pip install` here would need one under allow_internet=false.
set -eu

SRC="${SRC:-/src}"
REPO="$SRC/pyjwt"

cd "$REPO"
python3 -c "import jwt; print('module graph resolves:', jwt.__file__)"

echo "compile: pyjwt module graph loads cleanly"
