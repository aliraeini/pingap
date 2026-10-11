# Layers are ordered for the build cache: what changes least goes first, and
# the npm and cargo caches persist across builds in BuildKit/buildah cache
# mounts. Pass the commit for `pingap --version`, as .git is not sent:
#   docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD) .
FROM node:24-alpine AS webbuilder

WORKDIR /pingap/web
# The dependencies first: they are installed again only when the lockfile
# changes, not on every edit of the sources.
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
  npm ci
COPY web ./
# What `make build-web` does, without the Makefile in this stage
RUN npm run build \
  && find dist -name .DS_Store -delete

# Release toolchain - keep in step with the `toolchain:` pins in
# .github/workflows/publish.yml. The Debian release is pinned so it moves only
# together with the runtime stage below.
FROM rust:1.98.1-trixie AS builder

RUN  apt-get update \
  && apt-get install -y cmake libclang-dev wget gnupg ca-certificates lsb-release \
                        protobuf-compiler --no-install-recommends

RUN rustup target list --installed

COPY .  /pingap
# admin web assets are embedded from dist/ at compile time (src/plugin/admin.rs)
COPY --from=webbuilder /pingap/web/dist /pingap/dist

# Declared next to their only use, so a new value reruns the build step alone
ARG BUILD_ARGS=""
ARG GIT_SHA=""
# The registry and target/ live in cache mounts, which are not part of the
# image: the binary is copied out of target/ for the stages below. Without a
# GIT_SHA, `pingap --version` shows "unknown" (see build.rs).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/pingap/target \
  cd /pingap \
  && if [ -n "$GIT_SHA" ]; then export VERGEN_GIT_SHA="$GIT_SHA"; fi \
  && cargo build --release ${BUILD_ARGS} \
  && ls -lh target/release \
  && cp target/release/pingap /usr/local/bin/pingap

# Opt-in variant (`--target distroless`). Keep it above the Debian stage:
# a plain `docker build .` builds the last stage, the default image.
FROM gcr.io/distroless/cc-debian13 AS distroless

COPY --from=builder /usr/local/bin/pingap /usr/local/bin/pingap

CMD ["pingap"]

# Same Debian release as the builder, so the binary runs on the glibc it was
# linked against.
FROM debian:trixie-slim

COPY --from=builder /etc/ssl /etc/ssl
COPY --from=builder /usr/local/bin/pingap /usr/local/bin/pingap
COPY --from=builder /pingap/entrypoint.sh /entrypoint.sh

RUN mkdir -p /opt/pingap/conf

CMD ["pingap"]

ENTRYPOINT ["/entrypoint.sh"]
