# syntax=docker/dockerfile:1
#
# Multi-stage build for the Label 309 CLI: the `cardanowall` binary — a
# standalone Proof-of-Existence verifier and toolkit for Cardano metadata
# label 309.
#
# The build context is the repository root, which is the standalone
# `cardanowall-cli` crate, so the build is self-contained: it copies the crate
# and resolves the `cardanowall` SDK dependency from crates.io.

# ---------------------------------------------------------------------------
# Stage 1 — builder. Compiles the release binary.
#
# rust:1-bookworm tracks the moving stable toolchain. The crate is rustls-only
# (no system OpenSSL), so the build needs no system libs beyond the base image.
#
# The `cardanowall` SDK releases in lockstep with this CLI, so a freshly tagged
# tree can carry a Cargo.lock whose SDK entry does not satisfy the exact
# registry pin in Cargo.toml — it still lacks its registry source + checksum
# (those exist only once the SDK is published), or it is a stale registry
# entry for an older SDK version. In exactly those cases cargo's conservative
# resolve (`cargo fetch`) re-resolves the SDK entry while keeping every other
# locked version, and the `--locked` build then proves the rest of the graph is
# exactly as committed. A lock that already satisfies the pin — registry source
# AND matching version — is used byte-for-byte: the gated branch never rewrites
# a good lock.
# ---------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

WORKDIR /build

COPY . .

RUN pin=$(grep -E '^cardanowall = "=' Cargo.toml | head -1 | sed -E 's/.*"=([^"]+)".*/\1/') \
 && test -n "$pin" \
 && entry=$(grep -A 2 '^name = "cardanowall"$' Cargo.lock || true) \
 && lock_version=$(printf '%s\n' "$entry" | grep '^version = ' | head -1 | sed -E 's/version = "([^"]+)"/\1/' || true) \
 && if printf '%s\n' "$entry" | grep -q '^source = "registry+' && [ "$lock_version" = "$pin" ]; then \
      echo "Cargo.lock already resolves cardanowall $pin from crates.io"; \
    else \
      echo "Cargo.lock entry (version ${lock_version:-none}) does not satisfy the =$pin registry pin; reconciling"; \
      cargo fetch; \
    fi \
 && cargo build --release --locked -p cardanowall-cli

# ---------------------------------------------------------------------------
# Stage 2 — runtime. A slim Debian with the binary and CA certificates.
#
# ca-certificates: `verify`, `submit`, and `inbox` egress over HTTPS (public
# Cardano explorers, Arweave/IPFS gateways, the configured service gateway),
# all through rustls, which loads the system trust store.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user with a real home: the CLI persists gateway
# profiles (~/.cardanowall/config.toml, 0600) and per-identity inbox cursors
# under the home directory. Mount a host directory there to keep them across
# runs: -v ~/.cardanowall:/home/cardanowall/.cardanowall
RUN groupadd --system --gid 1001 cardanowall \
 && useradd --system --create-home --uid 1001 --gid cardanowall cardanowall

COPY --from=builder /build/target/release/cardanowall /usr/local/bin/cardanowall

USER cardanowall
WORKDIR /home/cardanowall

# A CLI, not a service: no EXPOSE, no HEALTHCHECK. Arguments ride the
# entrypoint, e.g. `docker run --rm ghcr.io/cardanowall/label-309-cli verify …`.
ENTRYPOINT ["cardanowall"]
CMD ["--help"]
