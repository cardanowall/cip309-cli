# `cardanowall` — Label 309 standalone verifier & Proof-of-Existence CLI

A single, fast, dependency-free native binary for working with **Label 309 Proof
of Existence** on Cardano: verify a record, anchor a new one, sign off-host,
derive an identity from a seed, build/verify Merkle proofs, and read a sealed
inbox.

It is **gateway-agnostic**. Every networked command takes an explicit gateway
base URL (the full base, version segment included — e.g.
`https://cardanowall.com/api/v1`) and an opaque API key — the CLI is bound to no
particular operator. The hosted `cardanowall.com` service is one such gateway;
any server that implements the Label 309 gateway API works the same way. **`verify` needs no gateway operator
at all** — it talks only to public Cardano explorers (Koios/Blockfrost) and
public Arweave/IPFS gateways, so a proof can be checked with zero trust in the
issuer, their domain, or their server.

Built on the Rust Label 309 SDK (the `cardanowall` crate); a byte-parity twin of
the TypeScript and Python SDKs.

---

## Install

### Prebuilt binaries

Every tagged release attaches per-platform archives and a `SHA256SUMS`
manifest to the
[GitHub release](https://github.com/cardanowall/label-309-cli/releases):

| Platform            | Target                       | Archive                                       |
| ------------------- | ---------------------------- | --------------------------------------------- |
| Linux x86_64        | `x86_64-unknown-linux-musl`  | `cardanowall-vX.Y.Z-<target>.tar.gz` (static) |
| Linux ARM64         | `aarch64-unknown-linux-musl` | `cardanowall-vX.Y.Z-<target>.tar.gz` (static) |
| macOS Apple Silicon | `aarch64-apple-darwin`       | `cardanowall-vX.Y.Z-<target>.tar.gz`          |
| macOS Intel         | `x86_64-apple-darwin`        | `cardanowall-vX.Y.Z-<target>.tar.gz`          |
| Windows x86_64      | `x86_64-pc-windows-msvc`     | `cardanowall-vX.Y.Z-<target>.zip`             |

Download the archive for your platform, verify its checksum against
`SHA256SUMS`, and put the binary on your `PATH`:

```bash
VERSION=X.Y.Z                  # the release you are installing
TARGET=aarch64-apple-darwin    # your target from the table above
BASE="https://github.com/cardanowall/label-309-cli/releases/download/v$VERSION"

curl -fsSLO "$BASE/cardanowall-v$VERSION-$TARGET.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"
grep "cardanowall-v$VERSION-$TARGET.tar.gz" SHA256SUMS | sha256sum -c -   # macOS: shasum -a 256 -c -
tar -xzf "cardanowall-v$VERSION-$TARGET.tar.gz"
sudo install "cardanowall-v$VERSION-$TARGET/cardanowall" /usr/local/bin/
```

On Windows, download the `.zip`, verify it the same way, and unpack
`cardanowall.exe` (`Expand-Archive` in PowerShell).

### Container image

Tagged releases also publish a multi-arch (amd64 + arm64) image to GHCR:

```bash
docker run --rm ghcr.io/cardanowall/label-309-cli:latest \
  verify <tx-hash> --cardano-gateway https://api.koios.rest/api/v1

# Persist gateway profiles and inbox cursors across runs:
docker run --rm -v ~/.cardanowall:/home/cardanowall/.cardanowall \
  ghcr.io/cardanowall/label-309-cli:latest gateway list
```

Images are tagged `X.Y.Z` per release; `latest` tracks the newest final
release.

### crates.io

```bash
cargo install cardanowall-cli   # installs the `cardanowall` binary
```

### From source

```bash
# A release binary at target/release/cardanowall:
cargo build --release

# …or install `cardanowall` onto your PATH:
cargo install --path .
cardanowall --version          # cardanowall <ver> (git <sha>, built <date>)
```

Requires a recent stable Rust toolchain (the build fetches crates.io
dependencies). The resulting binary is fully self-contained — no Node, no
runtime dependencies.

---

## Quick start

```bash
# Save your gateway once (endpoint + API key; see docs/GUIDE.md for keys):
cardanowall gateway add prod --base-url https://cardanowall.com/api/v1

# Anchor a file's hash on Cardano (the bytes never leave your machine):
cardanowall submit --file ./contract.pdf --wait confirmed

# Anyone, anywhere verifies it with just the tx hash — no account, no trust:
cardanowall verify <tx-hash> --cardano-gateway https://api.koios.rest/api/v1
```

---

## What it does

Full task-oriented documentation with copy-pasteable examples for every
capability lives in **[docs/GUIDE.md](docs/GUIDE.md)** — start there. Run
`cardanowall <command> --help` for the authoritative flag list.

| Command       | What it does                                                                                       |
| ------------- | -------------------------------------------------------------------------------------------------- |
| `verify`      | Prove a record standalone against public explorers — no operator server, ever                      |
| `submit`      | Anchor hashes, files (optionally `--store` the bytes), Merkle roots, or pre-built records          |
| `attest`      | Anchor a whole release / dataset / commit range as ONE record (CI-oriented; receipts, certs)       |
| `seal`        | Encrypt one or more files to recipients and anchor the proof — hash public, content recipient-only |
| `inbox`       | Discover, list, and decrypt sealed records addressed to your identity                              |
| `identity`    | Generate a new identity (`--generate`) or inspect one: signing key + delivery addresses            |
| `sign`        | Off-host / air-gapped record signing (`prepare` → external signer → `assemble`)                    |
| `merkle`      | Offline Merkle tooling: build roots and leaves-lists, verify inclusion proofs                      |
| `certificate` | Build and offline-verify per-item inclusion certificates                                           |
| `gateway`     | Named gateway profiles (endpoint + API key), stored `0600`                                         |
| `completion`  | Shell completion scripts (bash / zsh / fish / powershell)                                          |

## Secrets & safety

Secrets are never required on the command line. Seeds and keys arrive via
`*-file` / `*-stdin` flags, environment variables, or a hidden TTY prompt —
exactly one source at a time, with conflicts rejected loudly and error
messages that never echo the value. The full precedence rules are in
[docs/GUIDE.md §10.3](docs/GUIDE.md#103-secrets-sources-and-precedence).

## Exit codes

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| `0`  | valid / success                                                    |
| `1`  | integrity-class failure (a cryptographic/structural check failed)  |
| `2`  | network-class failure (a fetch/transport error)                    |
| `3`  | pending (insufficient confirmations, or a `--wait` that timed out) |
| `4`  | CLI input error (bad arguments, missing required input)            |

`verify` maps the verifier's verdict straight through to `0/1/2/3`; on the
anchoring commands `1` also covers gateway rejections and the `--max-usd`
refusal. Details per command in [docs/GUIDE.md §10.1](docs/GUIDE.md#101-exit-codes).

## Service independence

`verify` proves a record using only the transaction metadata, the (optional)
content bytes, and a public blockchain explorer. It contacts no issuer server and
honors a deny-list so it cannot be steered back to a single operator. A proof you
verified once stays verifiable by anyone, forever, with any Label 309 tooling.

## Related repositories

This CLI is one of the Label 309 reference projects:

- [`label-309`](https://github.com/cardanowall/label-309) — the Label 309 standard:
  prose spec, CDDL, JSON schemas, registries, and the conformance vectors.
- [`label-309-rs`](https://github.com/cardanowall/label-309-rs) — the Rust SDK crate
  `cardanowall` this CLI is built on.
- [`label-309-ts`](https://github.com/cardanowall/label-309-ts) — the TypeScript SDKs.
- [`label-309-py`](https://github.com/cardanowall/label-309-py) — the Python SDK.

## License

Apache-2.0.
