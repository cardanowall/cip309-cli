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

Publishing also draws on a **funded prepaid balance**: the gateway builds and
pays for the Cardano transaction, then debits your balance, so the first
`submit` fails until the account behind your key holds credit. On the hosted
service you top up through the operator; on `cardanowall.com`, that is the
account page. On a gateway you run yourself, credit the account from its control
plane (see [`label-309-gateway`](https://github.com/cardanowall/label-309-gateway)).
Verification needs no balance at all.

### 1.2 Save a gateway profile

Type the endpoint once, use it everywhere. Profiles live in
`~/.cardanowall/config.toml` (written `0600`); the API key is prompted for,
never passed on the command line:

```bash
cardanowall gateway add prod --base-url https://cardanowall.com/api/v1
cardanowall gateway use prod
cardanowall gateway list
```

Two more manage a saved profile: `gateway show <name>` prints one profile with
its key masked, and `gateway remove <name>` deletes it. `gateway show <name>
--reveal` prints the full API key to stdout (an explicit opt-in, since the key
is already stored plaintext in the config file) and writes a one-line caution to
stderr so capturing it in a log is a conscious act.

```bash
cardanowall gateway show prod
cardanowall gateway remove staging
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

### 1.4 Shell completion

`completion` prints a completion script for your shell (`bash`, `zsh`, `fish`,
or `powershell`). Source it from your shell's startup file so command and flag
names complete as you type:

```bash
# zsh: write the script somewhere on your $fpath, e.g.
cardanowall completion zsh > ~/.zfunc/_cardanowall

# bash: source it from ~/.bashrc
cardanowall completion bash > ~/.local/share/bash-completion/completions/cardanowall
```

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
anchor the digest directly — no file I/O at all. `--hash` is repeatable: each
`--hash` publishes one content item. A bare digest takes `--hash-alg` (default
`sha2-256`); an `alg:digest` spec, or a comma-separated list of them, co-hashes
one item under several algorithms.

```bash
cardanowall submit --hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
cardanowall submit --hash <digest-one> --hash <digest-two> --hash-alg sha2-256
cardanowall submit --hash sha2-256:<digest>,blake2b-256:<digest>
```

`--hash-alg` selects `sha2-256` (default) or `blake2b-256`; it is repeatable, so
`--file --hash-alg sha2-256 --hash-alg blake2b-256` co-hashes the file under
both. The two algorithms are the only ones the registry defines.

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
see [§5.6](#56-authorship-of-sealed-records).

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
content itself is encrypted and stored as ciphertext. The content is encrypted
either **to the recipients you name** ([§5.4](#54-seal-to-others)) or **to a
shared passphrase** ([§5.5](#55-seal-to-a-passphrase)) — never both in one
record. Only the intended reader can open it; everyone else — including the
gateway and the storage network — sees random bytes.

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

By default each item is hashed under `sha2-256`. `--hash-alg` selects
`sha2-256` (default) or `blake2b-256` and is repeatable, so co-hashing an item
under both binds two digests into the sealed record — the same content-hash
choice `submit` offers ([§2.2](#22-from-a-precomputed-digest)). The two
algorithms are the only ones the registry defines, and they behave identically
in every seal mode (recipients, `--to-self`, or `--passphrase`):

```bash
printf '%s' "$SEED" | cardanowall seal --file ./draft.pdf \
  --to age1lnaqhwme7uv0y8daecmcry6ax9v5gq43sq0d24z9cwd39wg4qhysehy6zz \
  --hash-alg sha2-256 --hash-alg blake2b-256 --seed-stdin
```

### 5.5 Seal to a passphrase

Not everyone you deliver to has a Label 309 identity. `--passphrase` seals the
record to a **shared secret** instead of a recipient key: anyone who knows the
passphrase can open it, and no delivery address is involved at all. Sealing to
a passphrase and sealing to recipients are mutually exclusive — a record is
sealed one way or the other, and combining `--passphrase` with `--to` /
`--to-self` is refused before any file is read.

Pass the secret out-of-band, never on the command line (argv leaks into shell
history, `ps`, and CI logs): from stdin, from a file, or the
`CARDANOWALL_PASSPHRASE` environment variable.

```bash
printf '%s' "$PASSPHRASE" | cardanowall seal --file ./report.pdf --passphrase-stdin
# …or from a file:
cardanowall seal --file ./report.pdf --passphrase-file ./secret.txt
```

The recipient opens it with the same passphrase — no key and no inbox scan (a
passphrase record is addressed to no identity, so `inbox sync` never matches
it). Hand them the transaction hash and the passphrase out-of-band; they
decrypt directly:

```bash
cardanowall inbox decrypt <tx-hash> --passphrase-file ./secret.txt --out ./report.pdf

# `verify` opens it too, and re-checks the plaintext against the on-chain hash:
cardanowall verify <tx-hash> --passphrase-file ./secret.txt
```

Everything else works exactly as with recipient sealing: `--file` is
repeatable (one record, many items), `--sign` and `--supersedes` behave
identically, and re-running produces a fresh record — a new Argon2id salt every
time, so a passphrase record never reveals that it repeats earlier content. A
passphrase record carries no recipient slots, so the recipient-capacity limit
of [§5.8](#58-capacity) never binds.

The strength of a passphrase seal is the strength of the passphrase: choose a
long, high-entropy one. Argon2id (memory-hard) raises the cost of guessing,
but a weak passphrase is still weak.

The Argon2id work factors default to the registry floor (`m` = 65536 KiB,
`t` = 3, `p` = 4). `--passphrase-m` (memory KiB), `--passphrase-t` (iterations),
and `--passphrase-p` (parallelism) raise them for a stronger KDF at more work
per open; a value below the floor is refused, and the flags apply only to a
passphrase seal. The effective parameters are recorded in the `--receipt-out`
JSON.

```bash
cardanowall seal --file ./report.pdf --passphrase-file ./secret.txt \
  --passphrase-m 131072 --passphrase-t 4
```

### 5.6 Authorship of sealed records

`--sign` additionally signs the record with the seed's identity key. It is a
separate opt-in because the questions are independent: _who can read this_
(the `--to` list) versus _who claims to have sent it_ (the signature). An
unsigned sealed record is deliberately sender-anonymous.

```bash
printf '%s' "$SEED" | cardanowall seal --file ./draft.pdf --to <address> --sign --seed-stdin
```

### 5.7 Receiving: the inbox cycle

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

`sync` and `list` match **recipient-key** slots only. A record sealed to a
passphrase is addressed to no identity, so it never appears in the inbox. Open a
passphrase record directly by its transaction reference instead (see
[§5.5](#55-seal-to-a-passphrase)):

```bash
cardanowall inbox decrypt <tx-hash> --passphrase-file ./secret.txt --out ./received.pdf
```

Instead of a seed, you can give the recipient commands the raw recipient secret
directly with `--secret-key` (or `CARDANOWALL_RECIPIENT_KEY`): a 32-byte value
as 64-char hex. It is **KEM-agnostic**, so the same flag carries an X25519
private key or an X-Wing decapsulation seed, and the CLI dispatches on the sealed
record's KEM. As with every secret, prefer `--secret-key-file` /
`--secret-key-stdin` over the bare flag.

#### Decrypting a record with more than one item

One record can carry several items, and a record can seal **each item to a
different recipient** — three files where only two are addressed to you.
`inbox decrypt <tx-hash>` handles that gracefully: it opens **every item
addressed to your key or passphrase**, writes each one, and **silently skips
the items sealed to someone else** — a not-for-you item is expected, not an
error, so it never fails the command. Addressability for a recipient-sealed
item is decided from the on-chain slots alone, so an item you cannot open is
never even downloaded.

With more than one item, `--out` is a filename **prefix**: each opened item
lands at `<prefix>.item-<N>.bin`, where `N` is its index in the record.

```bash
# A 3-item record where items 0 and 2 are sealed to you and item 1 is not:
printf '%s' "$SEED" | cardanowall inbox decrypt <tx-hash> --seed-stdin --out ./received
#   → writes ./received.item-0.bin and ./received.item-2.bin
#   → skips item 1 (sealed to another recipient) and still exits 0
```

If no item is sealed to you, the command says so plainly (`0 of N items … are
sealed to your key or passphrase`) and exits 0. A genuine problem on an item
you _are_ addressed to — tampered ciphertext, an unreachable blob, a
deny-listed host — still fails.

To open exactly one item, name it with `--item <N>`; in that mode the command
is strict — if that specific item is not sealed to your key, it is an error.
A recipient key opens only recipient-sealed items and a passphrase opens only
passphrase-sealed items, so supply whichever the record was sealed with (or
both, to sweep a mixed record):

```bash
printf '%s' "$SEED" | cardanowall inbox decrypt <tx-hash> --seed-stdin --item 2 --out ./just-that-one.bin
```

#### What `decrypt` reports

Alongside the recovered plaintext, `decrypt` reports the record's **authorship**,
since a recipient usually wants to know who sent what they just opened. In
`--json` mode a `record_signatures` object carries `signature_count` and a
per-signature verdict; an unsigned record says so explicitly (`signature_count`
of `0`, a valid and sender-anonymous sealed PoE). A record-level signature that
verifies fully reads `valid`; a wallet-path signature whose cryptographic check
passed but whose wallet-address binding this flow does not resolve reads
`address-unverified`, and the transcript points you at `cardanowall verify <tx>`
for that full binding.

In `--json` mode `--out` is **required**: the JSON results object owns stdout, so
the recovered plaintext must be written to a file rather than share the stream.
Passing `--json` without `--out` is an input error (exit `4`).

### 5.8 Capacity

| Address kind        | Security            | Recipients per record |
| ------------------- | ------------------- | --------------------- |
| `age1…` (X25519)    | classical           | ~144                  |
| `age1pqc…` (X-Wing) | post-quantum hybrid | ~11                   |

An over-capacity recipient set is refused up front, before any quote or
upload, with a clear error. Larger audiences: split across records.

### 5.9 Resuming a failed sealed publish

A recipient seal encrypts every item, uploads each ciphertext to permanent
storage (paying for it), then publishes the record. If the run dies **after** a
ciphertext upload has succeeded but before the record is published (a dropped
connection, a machine reboot mid-CI), that storage work is already paid for, and
re-running from scratch would re-encrypt and pay for it a second time.

To make that recoverable, a failed recipient seal writes a **resume-state file**
before it exits: `<seal-fingerprint>.l309-seal-resume.json` in the current
directory (relocate it with `--resume-state <path>`). It records the completed
uploads (storage URI, byte count, ciphertext hash) and the record to publish. It
holds **no key material, no passphrase, no plaintext**, so it is safe to keep and
to hand between machines. Resume the publish by pointing `--resume` at it:

```bash
cardanowall seal --resume <seal-fingerprint>.l309-seal-resume.json
```

`--resume` takes **none** of the original input flags (`--file`, `--to`,
`--to-self`, `--hash-alg`, `--supersedes`, `--sign`): the record to publish is
already fixed in the state file. It re-quotes, finishes only the uploads that
did not complete (reusing every one already paid for), and publishes. If the
original run was signed (`--sign`), the seed is required again (the signature is
regenerated, never persisted), so supply it the same way as before.

On success the resume-state file has served its purpose and is removed
automatically.

Because a resume-state file drives a real publish, treat it like a command line
you are about to run: it holds no secrets, but resume only a file you created
yourself. The gateway is always taken from your own flags, environment, or
profile and never from the file, so a swapped state file cannot redirect your
bearer key to another endpoint; if the file names a gateway that disagrees with
where you are resuming, the CLI stops and says so. When your original input files
are still on disk, the CLI re-hashes them and refuses to publish if they no
longer match the sealed record, so a tampered file cannot publish a record for
content you never sealed (`--skip-plaintext-recheck` waives that re-check, for
use only when the files have moved, such as a later CI stage). And before any
network call, `seal --resume` prints exactly what it will publish (the gateway,
the recipient count and KEM, the supersedes link, signing, and each item's file
and digests), so you can confirm it is the publish you meant.

**Passphrase seals cannot be resumed.** The prepared per-item state a passphrase
seal holds is derived from the passphrase and is never written to disk, so there
is nothing to resume from; a passphrase run writes no resume-state file. Re-run
it from the start instead (a fresh Argon2id salt makes it a brand-new record
either way).

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

### 6.1 Attaching an already-pinned mirror: `--uri`

`--store` uploads the bytes and mints a fresh `ar://` address for them. When
the content is **already** pinned somewhere — you uploaded it to Arweave or
IPFS yourself, or it lives at a known content address — attach that address
directly with `--uri` and skip the upload:

```bash
cardanowall submit --file ./whitepaper.pdf \
  --uri ar://<43-char-txid> \
  --uri ipfs://<cid>
```

`--uri` is repeatable, takes `ar://` or `ipfs://` addresses, and attaches them
to every `--hash` / `--file` item. It is independent of `--store`: use
`--store` to upload-and-bind, `--uri` to bind an existing mirror, or both
together (the freshly uploaded `ar://` follows your explicit mirrors in the
record). A verifier fetches from these addresses and checks the bytes against
the anchored hash, exactly as it does for `--store`. Mirrors attach to content
items only — not to `--merkle` (which carries its own leaves-list address) or
`--record` (published verbatim).

`attest` accepts `--uri` too, on the same terms, when it anchors a **single**
leaf (one `--paths` file, one `--commits` commit, or one `--leaf`) — the case
that publishes a plain `items[]` record, the direct analog of `submit`. It does
not apply to a Merkle record (2+ leaves): that shape binds its leaves-list
address through `--publish full-tree` ([§4.5](#45-full-tree-vs-root-only)), and
passing `--uri` there is refused.

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

Available on every anchoring command: `submit` (`--hash`, `--file`, and
`--merkle` modes), `attest` (all leaf sources), and `seal` — a superseding
record can be public or sealed. A pre-built `submit --record` carries its own
supersedes field inside its bytes, so it takes no `--supersedes` flag.

```bash
# Supersede an earlier sealed record with an updated one:
printf '%s' "$SEED" | cardanowall seal --file ./contract-v2.pdf --to <address> \
  --supersedes 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b \
  --seed-stdin
```

---

## 8. Air-gapped and KMS signing

When the signing key must never touch a networked machine (an offline laptop,
an HSM, a cloud KMS), split the flow: build the exact bytes to sign, sign them
externally, assemble the signed record, and publish it byte-for-byte. The
`--hash` form builds the record for you from a content digest, so nothing but
the hash and the public key crosses each boundary:

```bash
# 1. On any machine: build the record from a content digest and emit the
#    signing envelope (the bytes to sign, plus the record they belong to).
cardanowall sign prepare --hash <hex32> --signer-pubkey <ed25519-pubkey-hex> > prepared.json

# 2. On the isolated signer: produce a raw 64-byte Ed25519 signature over the
#    envelope's `sig_structure_hex` (any KMS/HSM that signs Ed25519 works).

# 3. Back online: attach the signature. `assemble` reads the record and the
#    prepare mode from prepared.json; the output is byte-identical to
#    in-process signing.
cardanowall sign assemble --signer-pubkey <ed25519-pubkey-hex> \
  --signature <64-byte-signature-hex> --in prepared.json > signed-record.hex

# 4. Publish the finished record verbatim.
cardanowall submit --record signed-record.hex --wait confirmed
```

To sign a record you have **already built** (a multi-item or sealed record, or
one produced by another Label 309 tool), pass it to `prepare` and `assemble`
with `--in <record>` in place of `--hash`; the flow is otherwise identical. Both
accept CBOR hex, raw CBOR, or JSON, from a file or stdin.

`submit --record` is also the general escape hatch: ANY structurally valid
Label 309 record — however you built it — publishes byte-for-byte (hex text
or raw CBOR, from a file or `-` for stdin). It is validated locally first, so
a malformed record fails fast (exit `4` with the validator's error codes)
without consuming a quote.

### 8.1 Hardware signers: CIP-8 hashed mode

Some hardware and KMS signers cannot sign a payload larger than a fixed internal
buffer. For those, `--hashed` shifts what crosses the signing boundary: instead
of the full COSE `Sig_structure`, the signer commits to its 28-byte
BLAKE2b-224 digest (`to_sign_hash_hex` in the prepare envelope). Software signers
should leave it off; the default non-hashed mode signs the full payload
directly.

Pass `--hashed` to **both** steps. `prepare --hashed` marks its envelope;
`assemble --hashed` attaches the signature and stamps the record's `hashed`
header so any verifier reconstructs the same payload the signer saw. The flag
must match on both sides: `assemble` refuses (exit `4`) a `--hashed` that
disagrees with what `prepare` recorded, rather than emit a signature that will
never verify.

```bash
cardanowall sign prepare --hash <hex32> --signer-pubkey <pub> --hashed > prepared.json
# … the signer signs prepared.json's 28-byte to_sign_hash_hex …
cardanowall sign assemble --signer-pubkey <pub> \
  --signature <64-byte-signature-hex> --hashed --in prepared.json > signed-record.hex
```

For one-machine signing without the ceremony, `sign record` signs in-process,
from a content digest with `--hash` or from a pre-built record with `--in`:

```bash
printf '%s' "$SEED" | cardanowall sign record --seed-stdin --hash <hex32> --json
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

The default-mode transcript includes a **`Record:`** section that echoes the
record's own committed claims (the per-item digest map, any storage `uris`, the
Merkle commitments, and the `supersedes` pointer), so you read the values on
chain, not only each check's pass/fail. Add `--pretty` to pretty-print `--json`.
Two flags trade completeness for speed or offline use: `--no-fetch` skips every
content fetch (item URIs, sealed ciphertext, Merkle leaves-lists) while still
resolving the transaction, and `--max-fetch-bytes <n>` aborts any single fetch
that exceeds a byte ceiling (reported as `CONTENT_FETCH_LIMIT_EXCEEDED`, a
statement about your policy, never about the record). Verification defaults to
Cardano mainnet; add `--network preprod` for a record anchored on the preprod
test network.

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

By default `verify` resolves public data sources with no configuration: the
Cardano transaction comes from the Koios mainnet API, and `ar://` content is
fetched from a built-in rotation of public Arweave gateways (`turbo-gateway.com`,
`arweave.net`, `permagate.io`). There is **no** default IPFS gateway: an
`ipfs://` URI is fetched only when you supply `--ipfs-gateway`, and declined
otherwise. `--cardano-gateway`, `--arweave-gateway`, and `--ipfs-gateway` (each
repeatable) override these; point them at your own infrastructure to keep every
hop under your control.

#### Verifying a record without the chain

`--record <path>` verifies a Label 309 record body straight from a file (raw
canonical CBOR or its hex-text encoding), with no transaction to resolve and no
Cardano gateway involved. It runs the same structural, signature, and content
checks over the supplied bytes, which makes it a **producer pre-submission
check** (is the record I am about to publish well-formed and correctly signed?),
an archival re-validation, or a conformance-vector check. It is mutually
exclusive with the `<tx-hash>` argument.

```bash
# Well-formedness + signature check on a record before you publish it:
cardanowall verify --record ./record.cbor
```

Local mode proves everything intrinsic to the bytes (structure, record
signatures, and the content-hash match when the content is supplied), but it
knows **nothing about the chain**: with no transaction there is no block time,
slot, or confirmation depth, and the report honestly omits them. If you hold
those facts out of band (from an explorer, say) assert them with `--block-time`,
`--slot`, and `--confirmations`; supplying `--confirmations` turns the
confirmation-depth gate back on against `--threshold`. They are caller-asserted,
so the report attributes them to you, not to a resolved transaction.

#### Supplying content out of band

When you already hold a sealed item's ciphertext or a commitment's leaves-list
locally, hand it to the verifier directly instead of having it fetched.
`--ciphertext <item-index>=<path>` supplies the ciphertext for a sealed item and
`--merkle-leaves <merkle-index>=<path>` supplies a leaves-list, each keyed by the
claim's index in the record, each repeatable. So a recipient who saved the
ciphertext can re-verify a sealed delivery with no storage fetch at all:

```bash
printf '%s' "$KEY_HEX" | cardanowall verify <tx-hash> \
  --secret-key-stdin \
  --ciphertext 0=./item-0.ciphertext
```

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

The exit code separates the three ways this can go wrong: a proof that is
well-formed but does **not** recompute to the root is an inclusion failure
(exit `1`); a proof file that is missing or unreadable is a network/IO error
(exit `2`); and a proof file that is present but malformed (bad JSON, bad hex,
a schema-invalid field) is an input error (exit `4`). Only exit `1` is a
verdict about the proof itself.

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
| `CARDANOWALL_RECIPIENT_KEY`                | `--secret-key`         | recipient secret key(s): X25519 private key or X-Wing decap seed      |
| `CARDANOWALL_PASSPHRASE`                   | `--passphrase`         | shared-secret passphrase for a passphrase seal or open                |
| `CARDANOWALL_CARDANO_GATEWAY`              | `--cardano-gateway`    | Koios-compatible explorer URL(s)                                      |
| `CARDANOWALL_ARWEAVE_GATEWAY`              | `--arweave-gateway`    | Arweave gateway URL(s)                                                |
| `CARDANOWALL_IPFS_GATEWAY`                 | `--ipfs-gateway`       | IPFS gateway URL(s)                                                   |
| `CARDANOWALL_BLOCKFROST_PROJECT_ID`        | `--blockfrost`         | Blockfrost fallback                                                   |
| `CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD` | `--threshold`          | confirmation depth                                                    |
| `CARDANOWALL_DENY_HOST`                    | `--deny-host`          | extra egress deny-list entries, appended to the built-in defaults     |
| `CARDANOWALL_DENY_HOSTS_REPLACE`           | `--deny-hosts-replace` | the entries REPLACE the built-in list (none listed ⇒ nothing refused) |
| `CARDANOWALL_CONFIG_PATH`                  | —                      | override the config file path                                         |

### 10.3 Secrets: sources and precedence

Each secret (a seed, a recipient key, or a **passphrase**) must come from
**exactly one** source; two at once is a hard error naming the conflict. All
three resolve in the same order:

1. `--seed-file` / `--secret-key-file` / `--passphrase-file <path>`
2. `--seed-stdin` / `--secret-key-stdin` / `--passphrase-stdin` (or the value `-`)
3. the raw `--seed` / `--secret-key` / `--passphrase` flag, which is
   **insecure** (argv leaks into shell history, `ps`, and CI logs) and prints a
   stderr warning
4. the matching environment variable (`CARDANOWALL_SEED`,
   `CARDANOWALL_RECIPIENT_KEY`, `CARDANOWALL_PASSPHRASE`)
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

| Field                                                                                                | Meaning                                                                                                                                                                                            |
| ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sealed{recipient_count, kem, to_self}`                                                              | the envelope facts                                                                                                                                                                                 |
| `items[]{hashes, sha2_256?, ar_uri, ciphertext_bytes}`                                               | per sealed file: `hashes` is the `alg`→digest map (the on-chain claim); `sha2_256` is a legacy convenience copy present ONLY when the item carries a sha2-256 digest; plus the ciphertext location |
| `record_hex`                                                                                         | the exact published canonical-CBOR record bytes                                                                                                                                                    |
| `signed`, `signer_ed25519`                                                                           | authorship facts                                                                                                                                                                                   |
| `passphrase_kdf{m, t, p}`                                                                            | the Argon2id work factors (present ONLY for a passphrase seal)                                                                                                                                     |
| `poe_id`, `tx_hash`, `status`, `gateway_base_url`, `quote{…}`, `wait{…}`, `balance_after_usd_micros` | as in the attest receipt                                                                                                                                                                           |

**Leaves list** — canonical CBOR (`cardano-poe-merkle-leaves-v1`), produced
by `merkle build` and uploaded by full-tree publishes; carries the leaf
digests, the root, the leaf count, and the advisory `leaf_alg`. Any
Label 309 tool decodes it.

**Inclusion certificate** (`label-309-inclusion-certificate-v1`) — JSON from
`attest --certificates-dir` or `certificate build`: the anchor (chain,
network, transaction, block time, explorer links), the tree facts
(`tree_alg`, `root`, `tree_size`), and per-item Merkle proofs with optional
labels. Self-contained; re-verifies offline with `certificate verify`.
