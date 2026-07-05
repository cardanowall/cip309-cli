# The `cardanowall` CLI handbook

Task-oriented guide to everything the CLI can do. Every command shown here is
runnable as written (substitute your own values for `<placeholders>`); every
capability links back to the same five ideas:

- **A proof of existence (PoE)** is a Cardano transaction carrying a Label 309
  record — a hash of your content, anchored at a block time nobody can move.
- **Your content never has to leave your machine.** Hash-only anchoring is the
  default everywhere.
- **Anyone can verify a proof** with only the transaction hash and a public
  blockchain explorer. No account, no API key, no trust in whoever published it.
- **A gateway** is a server that builds and pays for the Cardano transaction on
  your behalf and bills your prepaid balance. The CLI works with any server
  implementing the Label 309 gateway API.
- **An identity is a 32-byte seed.** It derives your signing key and your
  encrypted-delivery addresses. Seeds are cheap — mint one per purpose.

Contents:

1. [Getting set up](#1-getting-set-up)
2. [Anchor one file](#2-anchor-one-file)
3. [Prove authorship: identities and signing](#3-prove-authorship-identities-and-signing)
4. [Anchor many things at once: `attest`](#4-anchor-many-things-at-once-attest)
5. [Sealed delivery: encrypt to recipients](#5-sealed-delivery-encrypt-to-recipients)
6. [Public attachments: `--store`](#6-public-attachments---store)
7. [Superseding a record](#7-superseding-a-record)
8. [Air-gapped and KMS signing](#8-air-gapped-and-kms-signing)
9. [Verify everything](#9-verify-everything)
10. [Reference](#10-reference)

---

## 1. Getting set up

### 1.1 A gateway and an API key

Verification needs nothing — skip to [§9](#9-verify-everything) if you only
want to check proofs. Publishing needs a gateway endpoint and an API key:

- **Hosted:** create a key at `https://cardanowall.com/developers`. The base
  URL is `https://cardanowall.com/api/v1`.
- **Self-hosted:** run your own
  [`label-309-gateway`](https://github.com/cardanowall/label-309-gateway) and
  mint a key on its control plane. The CLI treats both identically — the key
  is an opaque bearer token, never inspected.

The base URL is always the **full** base including the API version segment
(`…/api/v1`); the CLI appends only resource paths to it.

### 1.2 Save a gateway profile

Type the endpoint once, use it everywhere. Profiles live in
`~/.cardanowall/config.toml` (written `0600`); the API key is prompted for,
never passed on the command line:

```bash
cardanowall gateway add prod --base-url https://cardanowall.com/api/v1
cardanowall gateway use prod
cardanowall gateway list
```

From here on, every publishing command in this guide resolves the gateway
automatically: **explicit flag → environment variable → active profile**.

### 1.3 Environment variables and scripting

CI environments usually skip profiles and use environment variables:

```bash
export CARDANOWALL_BASE_URL=https://cardanowall.com/api/v1
export CARDANOWALL_API_KEY=…        # from your CI secret store
```

Add `--json` to any command for a machine-readable summary on stdout
(diagnostics and errors go to stderr, as a structured
`{"error":{"code":…,"message":…,"command":…}}` object in JSON mode). The full variable
list is in [§10.2](#102-environment-variables).

---

## 2. Anchor one file

### 2.1 Hash-only (the default)

This is the bread-and-butter operation: prove a file existed now, without
revealing it. The CLI hashes the file locally, and only the 32-byte digest
goes on-chain — the bytes never leave your machine.

```bash
cardanowall submit --file ./contract.pdf --wait confirmed
```

You get back the record id, the Cardano transaction hash, and your
remaining balance. `--wait confirmed` blocks until the transaction crosses the
confirmation threshold (typically 5–6 minutes on mainnet); use
`--wait submitted` to return as soon as it reaches the network, or omit
`--wait` to return immediately after the gateway accepts it.

Re-running the same command is safe: the gateway deduplicates byte-identical
records, reports the original transaction, and does not debit again.

### 2.2 From a precomputed digest

When the hashing already happened elsewhere (a build system, a checksum file),
anchor the digest directly — no file I/O at all. `--hash` is repeatable: N
digests publish one record with N content items.

```bash
cardanowall submit --hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
cardanowall submit --hash <digest-one> --hash <digest-two> --alg sha2-256
```

`--alg` selects `sha2-256` (default) or `blake2b-256` and applies to all
digests in the record.

### 2.3 What you get back, and how anyone checks it

Every publish prints the transaction hash. That hash IS the proof handle —
give it to anyone and they can verify without trusting you or the gateway:

```bash
cardanowall verify <tx-hash> --cardano-gateway https://api.koios.rest/api/v1
```

To bind the proof to actual content, the verifier hashes their copy of the
file and compares against the record — see [§9](#9-verify-everything).

---

## 3. Prove authorship: identities and signing

A PoE is complete without any signature — the standard is issuer-agnostic.
Signing is what makes your anchors **addressable and attributable**: all
records signed by one key can be listed together, and anyone can check the
signature independently.

### 3.1 Generate an identity

An identity is a 32-byte seed. Mint one per purpose (a release pipeline, a
project, a personal notary) — never reuse a personal identity in CI:

```bash
cardanowall identity --generate
```

This prints the seed once — in checksummed `L309-SEED-1…` form and raw hex —
plus everything it derives: the Ed25519 signing key, and your two
encrypted-delivery addresses (`age1…` classical and `age1pqc…` post-quantum;
see [§5](#5-sealed-delivery-encrypt-to-recipients)). **Store the seed
immediately** (a password manager or offline backup); it cannot be recovered,
and whoever holds it controls the identity.

To re-inspect an identity later, feed the stored seed back:

```bash
printf '%s' "$SEED" | cardanowall identity --seed-stdin
```

### 3.2 Sign what you anchor

Every publishing command takes the same seed flags. Provide the seed via
stdin, a file, or the `CARDANOWALL_SEED` environment variable — never on the
command line (argv leaks into shell history and CI logs):

```bash
printf '%s' "$SEED" | cardanowall submit --file ./contract.pdf --seed-stdin
cardanowall attest --paths "dist/**" --seed-file /run/secrets/release-seed
```

On `seal`, signing is a separate explicit opt-in (`--sign`), because
encrypting **to** someone and claiming authorship are independent decisions —
see [§5.5](#55-authorship-of-sealed-records).

### 3.3 Verify a signature independently

`verify` checks record signatures as part of its normal run and reports the
signer's public key. To assert a specific expected signer, use the `signed`
profile and compare the reported key against the identity's
`ed25519_pubkey_hex` (from `cardanowall identity`):

```bash
cardanowall verify <tx-hash> --profile signed --json
```

A leaked seed exposes that identity's signature (and its sealed inbox) —
never funds. Rotate by minting a new identity.

---

## 4. Anchor many things at once: `attest`

`attest` anchors a whole set — release artifacts, a dataset, a commit range —
as **one** record with **one** on-chain fee, using a Merkle tree: each thing
becomes a leaf, the tree's root goes on-chain, and every leaf remains
individually provable. Built for CI, equally usable locally.

### 4.1 Files and globs

```bash
cardanowall attest \
  --paths "dist/**" --paths "SHA256SUMS" \
  --max-usd 1.00 \
  --receipt-out poe-receipt.json \
  --certificates-dir poe-certificates \
  --json
```

`--paths` takes literal paths and glob patterns. The selection is
deduplicated and byte-sorted by normalized relative path, and each leaf is
the streamed SHA-256 of the file bytes — so two runs over identical trees
produce the identical root, on any operating system. File bytes never leave
the machine; only hashes do.

One selected file publishes a plain single-item record; two or more build the
tree.

### 4.2 Git commit ranges

Anchor the commits themselves — each leaf is the SHA-256 of the raw commit
object bytes, ordered oldest-first:

```bash
cardanowall attest --commits v1.0..v1.1
cardanowall attest --commits HEAD --publish root
```

The receipt attributes every leaf to its commit hash.

### 4.3 Pre-hashed digests

When the hashes come from elsewhere — container image digests, Git LFS
object hashes, another system's exports — pass them straight through, in
argument order:

```bash
cardanowall attest --leaf <hex32> --leaf <hex32> --leaf <hex32>
```

### 4.4 The manifest, and `--anchor-manifest`

Files mode always writes a deterministic **`poe-manifest.json`**
(`--manifest-out` to relocate): byte-sorted `{path, size, sha2_256}` rows, no
timestamps. It is the human-readable companion — the wire record carries bare
digests, names live off-chain by design.

By default the manifest is NOT itself a leaf, so anyone can recompute the
root from the files alone. When the name↔hash binding itself must be
anchored, opt in:

```bash
cardanowall attest --paths "dist/**" --anchor-manifest
```

This appends SHA-256(manifest) as the final leaf. Projects that already ship
a `SHA256SUMS` file get the same effect by including it in `--paths`.

### 4.5 `full-tree` vs `root`-only

`--publish full-tree` (the default) uploads the canonical leaves-list to
permanent storage and binds its `ar://` address on-chain — anyone can verify
any leaf with no out-of-band data. `--publish root` publishes only the root
and the leaf count: the leaf set stays private, and you hand out inclusion
proofs selectively.

### 4.6 Receipts and inclusion certificates

`--receipt-out` writes a versioned JSON receipt (`label-309-attest-receipt-v1`)
capturing the whole run: the exact record bytes, the price breakdown, the
transaction, and the confirmation snapshot — your audit artifact
([§10.5](#105-file-formats)).

`--certificates-dir` (requires `--wait confirmed`, the default) writes one
**inclusion certificate** per leaf: a standalone JSON file embedding the full
Merkle proof, verifiable offline forever:

```bash
cardanowall certificate verify poe-certificates/0.certificate.json
```

### 4.7 CI: safe re-runs, price caps, exit codes

- **Re-runs are free and safe.** The root is a pure function of the file
  bytes, and the gateway deduplicates byte-identical records — a retried job
  reports the original anchor (`replayed` in the summary) with no second
  debit.
- **`--max-usd <x>`** refuses (exit `1`) before any upload or publish when the
  quoted price exceeds the cap — no FX surprise can overspend a pipeline.
- **Exit `3` means "still confirming", not failure.** On `--timeout` (default
  600 s) the receipt and summary are still written and the publish continues
  server-side; treat `3` as a warning in release jobs. Full code table in
  [§10.1](#101-exit-codes).

---

## 5. Sealed delivery: encrypt to recipients

### 5.1 What "sealed" means

A **sealed** PoE is an encrypted delivery with a public proof: the content
hash is on-chain (so existence and timing are provable by anyone), the
content itself is encrypted to the recipients you name and stored as
ciphertext. Only the named recipients can open it; everyone else — including
the gateway and the storage network — sees random bytes.

### 5.2 Addresses: yours and your peer's

Every identity has two delivery addresses, both printed by
`cardanowall identity`:

- `age1…` — classical X25519. Compact: roughly **144 recipients** fit one
  record.
- `age1pqc…` — hybrid X-Wing (ML-KEM-768 + X25519), the **post-quantum**
  form. Bigger slots: roughly **11 recipients** per record.

Ask your peer for either address (they run `cardanowall identity --generate`
if they have none, or read theirs from the CardanoWall web app). Addresses
are public — share them freely.

### 5.3 Seal to yourself

Encrypted personal archival: provable existence, content readable by you
alone. Sealing only to yourself defaults to the post-quantum form:

```bash
printf '%s' "$SEED" | cardanowall seal --file ./diary-2026.pdf --to-self --seed-stdin
```

### 5.4 Seal to others

```bash
printf '%s' "$SEED" | cardanowall seal --file ./draft.pdf \
  --to age1lnaqhwme7uv0y8daecmcry6ax9v5gq43sq0d24z9cwd39wg4qhysehy6zz \
  --to-self --seed-stdin --max-usd 2.00 --receipt-out seal-receipt.json
```

`--to` is repeatable and auto-detects the address kind by prefix. One seal
uses ONE kind: mixing `age1…` and `age1pqc…` recipients in a single record is
refused — a classical slot alongside post-quantum slots would silently void
the post-quantum protection for every recipient, so the standard forbids it.
Since every identity has both address forms, simply use the matching one.
`--to-self` adds your own decryption slot under the same kind, so you can
always re-open what you sent.

`--file` is repeatable too: each file becomes one item of a single record —
one anchor, one debit, every item sealed to the same recipients. Seal a
cover letter and its contract together, readable by the same keys:

```bash
printf '%s' "$SEED" | cardanowall seal \
  --file ./cover.pdf --file ./contract.pdf \
  --to age1lnaqhwme7uv0y8daecmcry6ax9v5gq43sq0d24z9cwd39wg4qhysehy6zz \
  --seed-stdin
```

Should the publish fail after any ciphertext upload already succeeded, the
error lists the completed uploads (storage URI, byte count, ciphertext
hash): that storage work was already paid for.

Re-running `seal` publishes a NEW record and debits again: encryption is
randomized by design, so a sealed record never reveals that it carries the
same content as an earlier one.

### 5.5 Authorship of sealed records

`--sign` additionally signs the record with the seed's identity key. It is a
separate opt-in because the questions are independent: _who can read this_
(the `--to` list) versus _who claims to have sent it_ (the signature). An
unsigned sealed record is deliberately sender-anonymous.

```bash
printf '%s' "$SEED" | cardanowall seal --file ./draft.pdf --to <address> --sign --seed-stdin
```

### 5.6 Receiving: the inbox cycle

The recipient side is three commands. `sync` scans the public records feed
and trial-decrypts locally — the gateway never learns which records are
yours; `list` shows what you can open; `decrypt` recovers the plaintext and
re-checks it against the on-chain hash:

```bash
printf '%s' "$SEED" | cardanowall inbox sync --seed-stdin
printf '%s' "$SEED" | cardanowall inbox list --seed-stdin --json
printf '%s' "$SEED" | cardanowall inbox decrypt <tx-hash> --seed-stdin --out ./received.pdf
```

`sync` keeps a per-identity cursor under `~/.cardanowall/`, so subsequent
runs only scan new records.

### 5.7 Capacity

| Address kind        | Security            | Recipients per record |
| ------------------- | ------------------- | --------------------- |
| `age1…` (X25519)    | classical           | ~144                  |
| `age1pqc…` (X-Wing) | post-quantum hybrid | ~11                   |

An over-capacity recipient set is refused up front, before any quote or
upload, with a clear error. Larger audiences: split across records.

---

## 6. Public attachments: `--store`

A record's `ar://` addresses can point at three kinds of bytes, and it helps
to keep them apart:

| What is stored                   | Produced by        | Who can read it                   |
| -------------------------------- | ------------------ | --------------------------------- |
| Ciphertext (sealed content)      | `seal`             | Only the named recipients         |
| A Merkle leaves list             | `attest` full-tree | Anyone (bare digests, no content) |
| The content itself, in the clear | `submit --store`   | **Anyone, forever**               |

The third form exists for content that SHOULD travel with the proof — a public
whitepaper, an open dataset, a press release. The standard is storage-agnostic
by design: a plain record may carry `uris` next to its hashes, and when there
is no encryption envelope those URIs point at the original bytes. `--store`
uploads the content to permanent storage and binds its `ar://` address into
the record:

```bash
cardanowall submit --file ./whitepaper.pdf --store --wait confirmed
```

Anyone can now fetch the content from the address in the record and check it
against the anchored hash — `verify --tx` does exactly that automatically.

**This is deliberate, irreversible publication.** Permanent storage cannot be
taken down; never `--store` anything private, personal, or licensed for
limited distribution — seal it ([§5](#5-sealed-delivery)) or anchor the hash
alone instead. The default without `--store` is always hash-only
([§2.1](#21-hash-only-the-default)): the bytes never leave your machine, and
you can still publish them elsewhere later — the anchored hash binds them
regardless of where they live.

---

## 7. Superseding a record

Content evolves. `--supersedes` publishes a new record that names the
transaction of the one it replaces, building a verifiable revision chain —
the old proof stays on-chain (nothing is ever deleted), but tooling can
follow the chain to the newest version:

```bash
cardanowall submit --file ./contract-v2.pdf \
  --supersedes 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b \
  --wait confirmed
```

Works on `submit` (`--hash` / `--file` modes) and on `attest` (all leaf
sources). A pre-built `--record` carries its own supersedes field inside its
bytes.

---

## 8. Air-gapped and KMS signing

When the signing key must never touch a networked machine — an offline
laptop, an HSM, a cloud KMS — split the flow: prepare the exact bytes to
sign, sign them externally, assemble the signed record, and publish it
byte-for-byte:

```bash
# 1. On any machine: build the canonical signing payload for the record.
cardanowall sign prepare --signer-pubkey <ed25519-pubkey-hex> --in record.cbor

# 2. On the isolated signer: produce a raw 64-byte Ed25519 signature over
#    those bytes (any KMS/HSM that signs Ed25519 works).

# 3. Back online: attach the signature — byte-identical to in-process signing.
cardanowall sign assemble --signer-pubkey <ed25519-pubkey-hex> \
  --signature <64-byte-signature-hex> --in record.cbor > signed-record.hex

# 4. Publish the finished record verbatim.
cardanowall submit --record signed-record.hex --wait confirmed
```

`submit --record` is also the general escape hatch: ANY structurally valid
Label 309 record — however you built it — publishes byte-for-byte (hex text
or raw CBOR, from a file or `-` for stdin). It is validated locally first, so
a malformed record fails fast (exit `4` with the validator's error codes)
without consuming a quote.

For one-machine signing without the ceremony, `sign record` signs in-process:

```bash
printf '%s' "$SEED" | cardanowall sign record --seed-stdin --in record.cbor --json
```

---

## 9. Verify everything

Verification is the point of the standard: **no server run by the publisher
is involved, ever.** Three verifiers cover every artifact this CLI produces.

### 9.1 A published record: `verify`

Fetches the transaction from a public Cardano explorer (Koios-compatible, or
Blockfrost as a fallback), validates the record's structure, checks
signatures, fetches referenced content and recomputes hashes:

```bash
cardanowall verify <tx-hash> --cardano-gateway https://api.koios.rest/api/v1

# Assert a stronger profile, machine-readable:
cardanowall verify <tx-hash> --profile signed --json

# A sealed record you are a recipient of — also decrypts and re-hashes:
printf '%s' "$KEY_HEX" | cardanowall verify <tx-hash> --secret-key-stdin
```

The exit code IS the verdict: `0` valid, `1` invalid, `2` could not fetch,
`3` valid but below the confirmation threshold. A deny-list prevents the
verifier from being silently steered back to a single operator's
infrastructure.

The deny list guards every outbound fetch the verifier makes: the record
`uris` and the explorer / Arweave / IPFS resolver hops taken to reach them.
`verify` has no service gateway of its own, so the resolvers you point it at
are checked against the same list. `--deny-host` entries are APPENDED to the
built-in defaults, so naming an extra host can never silently drop the
loopback/metadata protection. `--deny-hosts-replace` makes your entries the
whole list instead — the expert escape hatch for a private-network resolver
(an internal Arweave mirror, arlocal on loopback) the defaults would block;
replacing with no entries at all disables the deny list entirely.

### 9.2 An inclusion certificate, offline: `certificate verify`

A certificate from [`attest --certificates-dir`](#46-receipts-and-inclusion-certificates)
re-verifies from its own bytes forever — no network at all:

```bash
cardanowall certificate verify poe-certificates/0.certificate.json
```

It proves the inclusion math and echoes the anchor (transaction, block time,
explorer links) for you to confirm on any public explorer. Certificates can
also be built after the fact from any anchored Merkle record with
`certificate build`.

### 9.3 A raw Merkle proof: `merkle verify`

The lowest-level check, for proofs produced by any Label 309 tool:

```bash
cardanowall merkle verify --root <hex32> --leaf <hex32> --proof proof.json
```

`merkle build` is the offline counterpart — it derives the root and the
canonical leaves-list from a digest list (or from files to hash, with
`--file`) without publishing anything. Its `--leaf-alg` tags the leaves-list
with an advisory algorithm; the emitted artifact feeds `submit --merkle`
directly, and that `leaf_alg` is carried into the published leaves-list:

```bash
# Build the canonical leaves-list (hex), tagging the leaf algorithm:
cardanowall merkle build --file a.bin --file b.bin --leaf-alg sha2-256 --json \
  | jq -r .leaves_list_cbor_hex > leaves-list.hex

# Anchor the Merkle root; the leaf_alg is carried into the uploaded list:
cardanowall submit --merkle leaves-list.hex --wait confirmed
```

`submit --merkle` also takes the raw leaves-list CBOR bytes, or a plain text
file with one 64-hex leaf per line (which carries no `leaf_alg`).

---

## 10. Reference

### 10.1 Exit codes

| Code | Meaning                                                                                                         |
| ---- | --------------------------------------------------------------------------------------------------------------- |
| `0`  | success / verdict valid                                                                                         |
| `1`  | integrity-class failure: invalid verdict, gateway rejection, terminal publish failure, or a `--max-usd` refusal |
| `2`  | network-class failure: fetch, transport, upload, or unreadable file                                             |
| `3`  | pending: below the confirmation threshold, or a `--wait` that timed out (outputs complete, publish continues)   |
| `4`  | CLI input error: bad arguments, malformed values, conflicting flags                                             |

### 10.2 Environment variables

Consistent across every command; an explicit flag always wins over the
variable, which wins over the config file.

| Variable                                   | Flag                   | Meaning                                                               |
| ------------------------------------------ | ---------------------- | --------------------------------------------------------------------- |
| `CARDANOWALL_BASE_URL`                     | `--base-url`           | service gateway base URL                                              |
| `CARDANOWALL_API_KEY`                      | `--api-key`            | opaque bearer API key                                                 |
| `CARDANOWALL_SEED`                         | `--seed`               | seed (hex or `L309-SEED-1…`)                                          |
| `CARDANOWALL_RECIPIENT_KEY`                | `--secret-key`         | X25519 recipient key(s)                                               |
| `CARDANOWALL_CARDANO_GATEWAY`              | `--cardano-gateway`    | Koios-compatible explorer URL(s)                                      |
| `CARDANOWALL_ARWEAVE_GATEWAY`              | `--arweave-gateway`    | Arweave gateway URL(s)                                                |
| `CARDANOWALL_IPFS_GATEWAY`                 | `--ipfs-gateway`       | IPFS gateway URL(s)                                                   |
| `CARDANOWALL_BLOCKFROST_PROJECT_ID`        | `--blockfrost`         | Blockfrost fallback                                                   |
| `CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD` | `--threshold`          | confirmation depth                                                    |
| `CARDANOWALL_DENY_HOST`                    | `--deny-host`          | extra egress deny-list entries, appended to the built-in defaults     |
| `CARDANOWALL_DENY_HOSTS_REPLACE`           | `--deny-hosts-replace` | the entries REPLACE the built-in list (none listed ⇒ nothing refused) |
| `CARDANOWALL_CONFIG_PATH`                  | —                      | override the config file path                                         |

### 10.3 Secrets: sources and precedence

A seed or recipient key must come from **exactly one** source; two at once is
a hard error naming the conflict. Resolution order:

1. `--seed-file <path>` / `--secret-key-file <path>`
2. `--seed-stdin` / `--secret-key-stdin` (or the value `-`)
3. the raw `--seed` / `--secret-key` flag — **insecure** (argv leaks into
   shell history, `ps`, and CI logs); prints a stderr warning
4. the matching environment variable
5. a hidden interactive prompt (TTY only, when the secret is required)

Seeds are accepted as 64-digit hex or the checksummed `L309-SEED-1…` form.
Errors about malformed secrets report only length/offset — never the value.

### 10.4 Configuration file

`~/.cardanowall/config.toml` (override with `CARDANOWALL_CONFIG_PATH`),
written `0600`:

```toml
default_gateway = "prod"

[gateways.prod]
base_url = "https://cardanowall.com/api/v1"
api_key  = "…"

cardano_gateway = ["https://api.koios.rest/api/v1"]
arweave_gateway = "https://arweave.net"
ipfs_gateway    = "https://ipfs.io"
```

Service-gateway values resolve **flag → env → active profile** (no built-in
default). Public data sources (`--cardano-gateway` and friends) resolve
**flag → env → config top-level key → built-in default**.

### 10.5 File formats

All formats are versioned JSON with a `format` discriminator; none ever
carries key material.

**`poe-manifest.json`** (`label-309-poe-manifest-v1`) — written by
`attest --paths`; deterministic (byte-sorted, no timestamps).

| Field              | Meaning                                |
| ------------------ | -------------------------------------- |
| `files[].path`     | normalized relative path (byte-sorted) |
| `files[].size`     | byte count                             |
| `files[].sha2_256` | content hash = the record's leaf       |

**Attest receipt** (`label-309-attest-receipt-v1`) — written by
`attest --receipt-out`.

| Field                                                                           | Meaning                                                                   |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `mode`                                                                          | `paths` / `commits` / `leaves`                                            |
| `record_hex`                                                                    | the exact canonical record bytes published                                |
| `signed`, `signer_ed25519`                                                      | authorship facts                                                          |
| `items[]` or `merkle{root, leaf_count, publish, ar_uri}`                        | the record's content claim                                                |
| `commits[]`                                                                     | per-leaf commit attribution (git mode)                                    |
| `supersedes`                                                                    | the replaced transaction, when set                                        |
| `poe_id`, `tx_hash`, `status`, `gateway_base_url`                               | the anchor (and the gateway it was published through)                     |
| `quote{…}`                                                                      | the consumed price lock (omitted on a replayed run — nothing was debited) |
| `idempotency_key`, `replayed`                                                   | re-run facts                                                              |
| `manifest{path, sha2_256, anchored}`                                            | the companion manifest                                                    |
| `wait{target, reached, timed_out, block_height, block_time, num_confirmations}` | the confirmation snapshot                                                 |
| `certificates_dir`, `certificates_written`                                      | certificate output                                                        |
| `balance_after_usd_micros`                                                      | balance after the run (USD micro-cents)                                   |

**Seal receipt** (`label-309-seal-receipt-v1`) — written by
`seal --receipt-out`.

| Field                                                                                                | Meaning                                                  |
| ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `sealed{recipient_count, kem, to_self}`                                                              | the envelope facts                                       |
| `items[]{sha2_256, ar_uri, ciphertext_bytes}`                                                        | per sealed file: the content claim + ciphertext location |
| `record_hex`                                                                                         | the exact published canonical-CBOR record bytes          |
| `signed`, `signer_ed25519`                                                                           | authorship facts                                         |
| `poe_id`, `tx_hash`, `status`, `gateway_base_url`, `quote{…}`, `wait{…}`, `balance_after_usd_micros` | as in the attest receipt                                 |

**Leaves list** — canonical CBOR (`cardano-poe-merkle-leaves-v1`), produced
by `merkle build` and uploaded by full-tree publishes; carries the leaf
digests, the root, the leaf count, and the advisory `leaf_alg`. Any
Label 309 tool decodes it.

**Inclusion certificate** (`label-309-inclusion-certificate-v1`) — JSON from
`attest --certificates-dir` or `certificate build`: the anchor (chain,
network, transaction, block time, explorer links), the tree facts
(`tree_alg`, `root`, `tree_size`), and per-item Merkle proofs with optional
labels. Self-contained; re-verifies offline with `certificate verify`.
