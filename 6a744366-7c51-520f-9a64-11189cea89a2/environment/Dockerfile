# syntax=docker/dockerfile:1
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

COPY src.tgz /tmp/src.tgz
COPY scripts/ /scripts/
COPY config/ /config/
COPY install_validate_deps.sh /scripts/install_validate_deps.sh
RUN chmod +x /scripts/*.sh

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
