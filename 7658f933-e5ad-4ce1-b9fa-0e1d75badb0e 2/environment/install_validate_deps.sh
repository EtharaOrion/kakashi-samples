#!/usr/bin/env bash
# This image's own toolchain install already provides python3 and pyjwt
# installed editable, and grading for this task has no further third-party
# packages to add. This script exists to satisfy the non-OSS-Fuzz image
# contract and confirms the interpreter and the package are importable.
set -eu
command -v python3 >/dev/null
python3 -c "import jwt" >/dev/null
echo "install_validate_deps: python3 $(python3 --version) with jwt importable, no third-party deps needed"
