# Harbor ENVIRONMENT for PyJWT / CVE-2026-32597 (mode: patch-only).
#
# PyJWT is not an OSS-Fuzz project, so there is no upstream fuzzing image to
# build from: this is a plain Python toolchain image with an editable install
# of the package, the same way the recorded finding was reproduced.
#
# Grading replays the reproducer straight through the project's own run_poc.py
# harness, no manual instrumentation required.
#
# Layout:
#   $SRC              = /src
#   repository        = /src/pyjwt      (repo_to_patch "pyjwt")
#   reproduction harness = /src/pyjwt/run_poc.py
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV SRC=/src
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    patch=2.8-2 git=1:2.47.3-0+deb13u1 ca-certificates=20250419 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /output /logs/verifier $SRC

# --- vulnerable snapshot ------------------------------------------------------
COPY src.tgz /tmp/src.tgz
RUN mkdir -p $SRC/pyjwt && tar xzf /tmp/src.tgz -C $SRC/pyjwt && rm /tmp/src.tgz

# --- build, replay and regression entry points -------------------------------
COPY scripts/ $SRC/
RUN chmod +x $SRC/*.sh

# --- pre-install ---------------------------------------------------------
# Done at image build time so the agent's own first iteration is instant
# rather than paying an install on every compile.sh call.
#
# setuptools and wheel are installed explicitly because the verifier re-installs
# a freshly extracted tree with allow_internet=false. pyproject.toml's build
# backend needs setuptools>=77.0.3, and with no network pip cannot fetch it, so
# it has to already be present and the re-install has to skip build isolation.
RUN pip install --no-cache-dir setuptools==84.0.0 wheel==0.48.0 && \
    pip install --no-cache-dir -e $SRC/pyjwt pytest==9.1.1

# --- unprivileged identity for the verifier's editable install ---------------
# `pip install -e .` executes the project's own build step, which for a graded
# submission is agent-controlled code. The verifier runs as root, so without a
# lesser identity to drop to that build step is arbitrary code with the run of
# the filesystem. The oracle copies the tree, hands it to this account and
# installs as this account, so a build hook can write only inside the copy that
# is about to be discarded. No login, no shell, no password.
RUN useradd --create-home --uid 4242 --shell /usr/sbin/nologin qcbuild

# The image ships no reproducer and no crash transcript. Either one names the
# `crit` header the defect lives in, which is the finding the task asks for. The
# reproducers the stages replay are base64-embedded in tests/validate.py and
# never enter this image.

# --- pristine baseline, so `git diff` in the repo is exactly the agent's edits
RUN cd $SRC/pyjwt && \
    printf '__pycache__/\n*.pyc\n*.egg-info/\n.pytest_cache/\n' > .gitignore && \
    git init -q --separate-git-dir=/opt/harbor-baseline.git && \
    git config user.email harbor@localhost && \
    git config user.name "Harbor task baseline" && \
    git add -A && \
    git commit -q -m "pyjwt baseline"

# --- sanitized task config ---------------------------------------------------
COPY config/ /config/

ENV WORKSPACE_ROOT=/src
WORKDIR /src
