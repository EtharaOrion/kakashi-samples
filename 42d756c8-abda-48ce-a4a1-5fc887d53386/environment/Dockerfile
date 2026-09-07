# Build image for the rekor task.
FROM golang@sha256:c6a5b9308b3f3095e8fde83c8bf4d68bd101fce606c1a0a1394522542509dda9

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        patch \
        time \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

# /output is where the agent drops its artifacts. /logs/verifier is the grading side.
RUN mkdir -p /output /logs/verifier /src /out /scripts /config

COPY src.tgz /tmp/src.tgz
COPY scripts/ /scripts/
COPY config/ /config/
COPY install_validate_deps.sh /scripts/install_validate_deps.sh
RUN chmod +x /scripts/*.sh

# python for the grading side, kept apart from the module the agent builds
RUN bash /scripts/install_validate_deps.sh

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=mod \
    GOPATH=/go

# Warm the module cache while the image build still has network, so every graded
# run afterwards works offline, and prove the tree compiles. The binary and the
# compiled-object cache are both dropped afterwards: each stage rebuilds from
# whatever tree is in place, and shipping compiled objects of the source serves
# no purpose. Only the module cache is kept, which is what offline builds need.
RUN bash /scripts/prepare.sh \
    && cd /src/rekor \
    && go mod download all \
    && bash /scripts/compile.sh \
    && rm -f /out/parseharness \
    && go clean -cache

WORKDIR /src
