# syntax=docker/dockerfile:1
#
# Harbor VERIFIER environment for rekor (Go).
# Mirrors environment/Dockerfile (multi-arch golang manifest, CGO disabled) so the
# oracle's /scripts/*.sh, /src/rekor tree and Go module cache are present offline.
#
ARG TARGETARCH

# Both arch stages start from the same multi-arch golang manifest. The digest
# below is an OCI image index carrying linux/amd64 and linux/arm64, so BuildKit
# resolves the matching per-arch image automatically for each stage. Builds are
# pure Go with CGO disabled, so no arch-specific toolchain setup is required.
FROM --platform=linux/amd64 golang@sha256:c6a5b9308b3f3095e8fde83c8bf4d68bd101fce606c1a0a1394522542509dda9 AS base-amd64

FROM --platform=linux/arm64 golang@sha256:c6a5b9308b3f3095e8fde83c8bf4d68bd101fce606c1a0a1394522542509dda9 AS base-arm64

FROM base-${TARGETARCH}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        patch \
        time \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /output /logs/verifier /src /out /scripts /config

# The build assets -- pristine tree, /scripts, /config -- travel inside
# validate.py as base64 constants, so tests/ keeps to the canonical file set and
# this bundle needs no env/ directory. They are written back out HERE, at image
# build time, so every prebuild below is unchanged and nothing moves to grade
# time. validate.py is copied on its own first: the whole of tests/ lands in the
# final layer, which keeps an edit to a grader out of the Go build's cache path.
COPY validate.py /tests/validate.py
RUN python3 /tests/validate.py --materialize \
        --src-tgz /tmp/src.tgz --scripts-dir /scripts --config-dir /config

RUN bash /scripts/install_validate_deps.sh

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=mod \
    GOPATH=/go

RUN bash /scripts/prepare.sh \
    && cd /src/rekor \
    && go mod download all \
    && bash /scripts/compile.sh \
    && rm -f /out/parseharness \
    && go clean -cache

WORKDIR /src

# --------------------------------------------------------------------------- #
# Verifier layer.  [verifier].environment_mode = "separate" grades in a
# dedicated container Harbor builds from this tests/ directory, so the image
# must own /tests.  Built on the SAME base + toolchain as environment/Dockerfile
# (its build assets are embedded in validate.py) so a submission is graded
# under the toolchain it was produced against.  Only /logs/verifier and the
# submitted /output artifacts arrive at grade time.
# --------------------------------------------------------------------------- #
RUN mkdir -p /output /logs/verifier /tests
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
