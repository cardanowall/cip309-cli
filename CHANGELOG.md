# Changelog

All notable changes to the Label 309 CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` (the CLI) is pre-1.0. The command surface,
> flags, and output may change in backward-incompatible ways until a 1.0 release.
> Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.8.0] - 2026-07-02

### Changed

- Version alignment with the coordinated 0.8.0 release; no functional changes to the command surface. The binary is rebuilt against the `cardanowall` SDK 0.8.0.

## [0.7.1] - 2026-06-18

### Fixed

- Track the `cardanowall` SDK 0.7.1: `verify` retrieves Arweave content through the `turbo-gateway.com` fast-finality gateway and follows the gateway's same-domain sandbox-subdomain redirects (SSRF-safe — same registrable domain only, deny-host re-checked on every hop, `https`-only, three-hop cap). The dead default gateways `ar-io.net` and `g8way.io` are removed.

## [0.7.0] - 2026-06-16

### Added

- `cardanowall certificate build|verify` — build a Label 309 inclusion certificate (locate each target leaf in an off-chain leaves-list, compute its RFC 9162 inclusion proof, and emit the JSON certificate plus the optional COSE CBOR proof) and verify one offline from its own bytes. Exit codes pair with the verdict (`0` verified, `1` inclusion-failed, `2` IO/usage, `4` malformed input).

### Changed

- Track the `cardanowall` SDK 0.7.0: client base URLs now carry the full versioned API root (the API version segment lives in the configured base URL, not in client code), and the removed server-side verify path leaves `verify` as a purely standalone, no-server-trust operation.

### Fixed

- `submit`: the `--json` outcome renders `status` as its canonical wire string.

## [0.6.0] - 2026-06-13

### Security

- Secret material (seeds, secret keys, passphrases) never appears in error messages, warnings, or `Debug` output: a failure reports only a length or byte offset, and supplying a secret through more than one source is now a hard error instead of a silent precedence choice.

## [0.5.0] - 2026-06-12

### Changed

- Version alignment with the coordinated 0.5.0 release; no functional changes.

## [0.4.0] - 2026-06-11

### Changed

- Track the `cardanowall` SDK 0.4.0, which finalizes the sealed-PoE construction and de-chunks record fields (breaking wire-format changes — records sealed by earlier releases do not decrypt or verify under 0.4.0, and vice versa) and reworks verification around a four-state verdict.
- **BREAKING (`verify`):** Exit codes pair with the verdict — `0` valid, `3` pending, `2` unverifiable, `1` failed — and the `--json` report uses the reworked schema (camelCase fields, positional `items`/`merkle` results, severity-tagged issues). A deny-host violation dominates the outcome.
- `--no-fetch` governs content fetches only: item URIs, sealed ciphertext, and Merkle leaves-lists are not fetched (those claims report as not checked), while the transaction metadata is still resolved and verified on-chain.
- Seed inputs accept both the checksummed `L309-SEED-1…` form and raw hex.

### Added

- A run-global recipient keyring for sealed records: repeatable `--secret-key` (bare hex), `--secret-key-file`, and `--secret-key-stdin`; every supplied key is tried against every sealed item.

## [0.3.0] - 2026-06-06

### Changed

- Track the `cardanowall` SDK 0.3.0, which implements the finalized sealed-PoE scheme-1 construction (a breaking wire-format change for sealed envelopes) and hardened recipient decryption. The command surface and flags are unchanged.

## [0.2.0] - 2026-06-04

### Changed

- Rebranded to **Label 309** (help text and documentation). The `cardanowall` binary name and command set are unchanged.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 CLI (binary `cardanowall`).
