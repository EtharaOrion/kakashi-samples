# syntax=docker/dockerfile:1
ARG TARGETARCH

# Both arch stages start from the same multi-arch python:3.12-slim manifest.
# The digest below is an OCI image index carrying linux/amd64 and linux/arm64,
# so BuildKit resolves the matching per-arch image automatically for each stage.
FROM --platform=linux/amd64 python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS base-amd64

FROM --platform=linux/arm64 python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS base-arm64

FROM base-${TARGETARCH}

ENV SRC=/src
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    patch=2.8-2 git=1:2.47.3-0+deb13u1 ca-certificates=20250419 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /output /logs/verifier $SRC

COPY src.tgz /tmp/src.tgz
RUN mkdir -p $SRC/pyjwt && tar xzf /tmp/src.tgz -C $SRC/pyjwt && rm /tmp/src.tgz

COPY scripts/ $SRC/
RUN chmod +x $SRC/*.sh

RUN pip install --no-cache-dir setuptools==84.0.0 wheel==0.48.0 && \
    pip install --no-cache-dir -e $SRC/pyjwt pytest==9.1.1

RUN useradd --create-home --uid 4242 --shell /usr/sbin/nologin qcbuild

RUN cd $SRC/pyjwt && \
    printf '__pycache__/\n*.pyc\n*.egg-info/\n.pytest_cache/\n' > .gitignore && \
    git init -q --separate-git-dir=/opt/harbor-baseline.git && \
    git config user.email harbor@localhost && \
    git config user.name "Harbor task baseline" && \
    git add -A && \
    git commit -q -m "pyjwt baseline"

COPY config/ /config/

ENV WORKSPACE_ROOT=/src
WORKDIR /src
