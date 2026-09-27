#!/bin/bash -eu
# install_validate_deps.sh - the interpreter the judge and the grader run under.
#
# The judge is stdlib-only, so nothing is installed on its account.
#
# pytest is a different matter. The amd64 base builder carries TWO interpreters:
# its own /usr/local/bin/python3, which is what PATH resolves, and the
# distribution's /usr/bin/python3. `apt-get install python3-pytest` installs into
# the second one, so `python3 -m pytest` -- which is how tests/test.sh grades
# test_output.py -- still fails with "No module named pytest" and the whole run
# scores zero for a reason nothing reports. The arm64 leg builds on plain Ubuntu,
# where nothing guarantees an interpreter at all. Either way the interpreter is
# named here rather than assumed, and pytest is installed with pip so it targets
# the python3 that actually runs.
#
# The import check then asserts both halves, so a regression here fails the
# build rather than surfacing as a zero score at grade time.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-pip
    rm -rf /var/lib/apt/lists/*
fi

python3 -m pip install --no-cache-dir --disable-pip-version-check pytest

python3 - <<'PY'
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile
import pytest
if sys.version_info < (3, 8):
    raise SystemExit("the verifier needs python 3.8 or newer, found %s" % sys.version.split()[0])
print("validate deps ready on", sys.version.split()[0], "pytest", pytest.__version__)
PY
