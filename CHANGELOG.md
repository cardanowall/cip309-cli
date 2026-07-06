# Changelog

All notable changes to the Label 309 CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` (the CLI) is pre-1.0. The command surface,
> flags, and output may change in backward-incompatible ways until a 1.0 release.
> Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.11.0] - 2026-07-06

Built and tested against the `cardanowall` SDK 0.11.0.

### Added

- Co-hashing across the publishing commands: `--hash-alg` is repeatable on `submit`, `attest`, `seal`, and `sign`, so one record can commit to the same content under more than one digest (for example SHA2-256 plus BLAKE2b-256). The JSON output reports a per-item hashes map keyed by algorithm rather than a single digest.
- Passphrase sealing and opening. `seal --passphrase` wraps every item's content-encryption key from an Argon2id-derived key instead of recipient keys, so anyone holding the passphrase can open the record; `verify` and `inbox` accept the same `--passphrase` to open a passphrase-sealed record. Recipient and passphrase modes are mutually exclusive per record.
- `verify` gains a local record mode: `--record <file|->` validates and verifies a pre-fetched record with no network call, `--network` selects the chain for tx-reference verification, and out-of-band content is supplied with `--ciphertext` / `--merkle-leaves`. `--max-fetch-bytes` caps how many bytes any URI fetch may pull.
- `submit` and `attest` accept a repeatable `--uri` to attach a plural fetch-set to a single-leaf record; `--supersedes` links a record to the transaction it supersedes on `seal` and on `submit --merkle`.
- `sign prepare` / `sign assemble` gain a `--hashed` mode: the signer receives the already-hashed COSE `Sig_structure` for a constrained CIP-8 signer that hashes out of band.
- `seal --resume` recovers a sealed publish that failed after its ciphertext uploads were paid for, re-using the completed upload receipts from the seal receipt instead of re-encrypting and re-paying storage. The resume path resolves its gateway from a trusted source and binds to the saved state tamper-evidently.

### Changed

- `inbox decrypt` handles a multi-recipient record gracefully: it opens the slot addressed to the caller and skips the rest instead of failing the whole record, surfaces the record signer, and accepts KEM-agnostic raw recipient keys. Its JSON/`--out` contract is stabilized.
- `merkle-verify` exit codes are aligned with the rest of the CLI (a verification failure and a usage error are distinct, scriptable codes).

### Fixed

- `attest` and `submit` JSON no longer mislabel digests: the per-item hashes map is keyed by the actual algorithm, so a co-hashed item's digests are never conflated.

## [0.10.0] - 2026-07-05

Built and tested against the `cardanowall` SDK 0.10.0.

### Added

- `seal` takes a repeatable `--file`: each file becomes one item of a single sealed record (shared recipients, one KEM). The seal receipt (`label-309-seal-receipt-v1`) gains a top-level `record_hex` and per-item entries; if a publish fails after the ciphertext uploads are paid for, both the human and JSON error output list every completed upload receipt so the work is not lost.
- `submit --json` includes `record_hex` (the exact published record bytes) in every mode; `submit --merkle` accepts the canonical leaves-list artifact from `merkle build --leaf-alg` and carries its `leaf_alg` into the record.
- `--deny-hosts-replace` (config `deny_hosts_replace`, env `CARDANOWALL_DENY_HOSTS_REPLACE`) replaces the built-in SSRF deny list entirely, for a private-network resolver such as an internal Arweave mirror.

### Changed

- `--deny-host` entries now APPEND to the built-in deny list instead of replacing it, so naming an extra host can never silently drop the loopback/metadata protection. In `verify` and `certificate`, which have no service gateway, the help states the real scope: the deny list guards egress to URLs derived from untrusted on-chain records.
- The `attest` leaves-list upload and `submit --file --store` content upload now send a deterministic idempotency key, so a crash-and-retry between the paid upload and the publish never re-pays storage.

## [0.9.1] - 2026-07-04

No crate API or CLI behavior changes — distribution only.

### Changed

- The container image (`ghcr.io/cardanowall/label-309-cli`) now ships `git` and `jq` in the runtime stage: `attest --commits` works inside the container (it shells out to git), and CI wrappers that run the image as their job environment can map the attest receipt onto job outputs with jq.
- Release assets (the five prebuilt binary archives and `SHA256SUMS`) now carry SLSA build-provenance attestations; verify a download with `gh attestation verify <file> --repo cardanowall/label-309-cli`.

## [0.9.0] - 2026-07-03

### Added

- `cardanowall attest` — one command that anchors a set of files (`--paths`, glob-expanded, byte-sorted, streamed hashing), a commit range (`--commits`, raw commit objects via git), or pre-hashed digests (`--leaf`) as a Label 309 record. One leaf publishes as a plain content-hash record; two or more publish as an RFC 9162 Merkle commitment with the leaves list on Arweave (`--publish full-tree`, the default) or as a root-only commitment (`--publish root`). Writes a deterministic `label-309-poe-manifest-v1` companion (`--anchor-manifest` appends its hash as the final leaf) and a `label-309-attest-receipt-v1` receipt, and emits per-leaf inclusion certificates after confirmation (`--certificates-dir`). Re-runs are safe by default: records are deterministic, so the gateway's content dedup replays the existing record without a second debit (an explicit `--idempotency-key` is also supported, with the strict same-body contract); waits for on-chain confirmation (`--wait confirmed`, exit code 3 on timeout with complete outputs); refuses to publish above a price cap (`--max-usd`, re-checked if the quote is refreshed); optional Ed25519 record signing with the existing seed flags.
- `cardanowall seal` — publish a sealed PoE from the command line: the plaintext is hashed and encrypted locally (it is never uploaded in the clear), the ciphertext goes to Arweave, and the record carries one envelope slot per recipient. Recipients are age-style strings (`--to`, repeatable): classical x25519 and hybrid post-quantum X-Wing are auto-detected from the address form, one KEM per record — mixing refuses rather than downgrading. `--to-self` derives the sender's own slot from the seed (hybrid by default); `--sign` optionally signs the record, keeping encryption and authorship independent. Recipient capacity is pre-checked against the record-size ceiling with exact per-KEM limits, and sealed receipts use `label-309-seal-receipt-v1`.
- `submit --record <file|->` — publish a pre-built canonical record byte-for-byte after local structural validation. This closes the air-gap loop (`sign prepare` → external signer → `sign assemble` → `submit --record`) and makes every record shape the standard allows publishable from the command line.
- `submit`: `--hash` is repeatable (multi-item records), `--store` uploads the plaintext content and publishes it as a public attachment (`uris`), `--supersedes` (also on `attest`) links the record to the transaction it supersedes, and `--wait submitted|confirmed` with `--timeout` plus `--idempotency-key` complete the publish flow.

### Fixed

- Quote sizes are computed from the actual record — exact for content-hash records, a tight upper bound for Merkle records — instead of hardcoded constants that under-quoted signed Merkle records and made the gateway reject them at publish time.
- Non-UTF-8 paths are refused with a clear error instead of being lossily collapsed; a glob can no longer drop such a file from the leaf set silently.

### Changed

- Tagged releases now attach prebuilt per-platform binaries with a `SHA256SUMS` manifest and publish a container image `ghcr.io/cardanowall/label-309-cli`. The `cardanowall` SDK dependency is pinned exactly to the coordinated release version.

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
