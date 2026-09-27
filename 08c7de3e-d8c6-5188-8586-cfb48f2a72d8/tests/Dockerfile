# Harbor VERIFIER environment for PyJWT / CVE-2026-32597.
#
# [verifier].environment_mode = "separate" grades in a dedicated container, which
# Harbor builds from this directory. A separate verifier sets skip_tests_upload,
# so Harbor never stages the grader at run time and the image must own /tests
# itself; only /logs/verifier and the submitted /output artifacts arrive later.
# No PyJWT source, reproducer or patch is baked in: validate.py carries its own
# pristine tree as an embedded base64 archive.
#
# Base digest, apt pins and pip pins are held identical to environment/Dockerfile
# so a submission is graded under the same interpreter and toolchain it was
# produced against.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ENV DEBIAN_FRONTEND=noninteractive

# validate.py shells out to `patch` to apply the submitted fix.patch.
RUN apt-get update && apt-get install -y --no-install-recommends \
    patch=2.8-2 git=1:2.47.3-0+deb13u1 ca-certificates=20250419 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /output /logs/verifier

# setuptools and wheel must already be present: grading runs with no network and
# validate.py installs the extracted tree with --no-build-isolation, so pip
# cannot fetch the project's build backend. pytest backs the stage that replays
# the library's own suite.
RUN pip install --no-cache-dir \
    setuptools==84.0.0 \
    wheel==0.48.0 \
    pytest==9.1.1

# The editable install executes the submission's own build step, i.e.
# agent-controlled code. The verifier runs as root, so validate.build_identity()
# drops to this account to confine that step to the copy it is about to discard.
# Absent the account it silently installs as root, so it is required here.
RUN useradd --create-home --uid 4242 --shell /usr/sbin/nologin qcbuild

COPY . /tests
# The rubric judge and its optional compressor travel in tests/_judge/ and are
# staged by the COPY above at /tests/_judge/; test.sh invokes them by that path.
# They use only the Python standard library (urllib over the HTTPS endpoint), so
# no new packages are installed. JUDGE_WIRE + the API key arrive from
# [verifier.env]/Harbor at grade time; with no key the rubric channel is left
# unscored and the reward falls back to the deterministic channel alone.
ENV GRADER_HEADROOM_ENABLED=false
RUN chmod +x /tests/test.sh

WORKDIR /
