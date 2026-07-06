# Prepared-seal cross-SDK parity vectors

Byte-identical copies of the canonical cross-SDK vectors for the SDK-level
portable `prepared_seal_json_v1` artifact and its derivations. The Rust and
TypeScript SDKs consume the same files; any edit must be mirrored to every
copy in lockstep. Consumed by `tests/test_prepared_seal_vectors.py`.

Two producer paths share this vector set:

- **Recipient seal** (`single-item-*`, `multi-item-*`,
  `single-item-cohash-*`): every item sealed to a shared recipient set under
  one KEM. The `single-item-cohash-*` vector co-hashes one item under both
  `sha2-256` and `blake2b-256` (a two-entry `hashes` map bound into the slots
  MAC — the multi-hash sealed-prepare path). These pin the portable
  `prepared_seal_json_v1` artifact and the `"seal1-"` upload key.
- **Passphrase seal** (`single-item-passphrase`): a client-level passphrase
  seal delivering the content key through an Argon2id-stretched passphrase (an
  `enc.passphrase` block, no KEM slots). It has **no** portable
  `prepared_seal_json` form (nothing recipient-blind to serialize), so it pins
  the derived values only, and its upload key is `"pwseal1-"`.

Each vector pins, for a fully deterministic prepare run:

- the exact `prepared_seal_json_v1` serialization (`prepared_seal_json`),
  recipient path only — compact UTF-8 JSON, keys sorted lexicographically by
  byte order at every nesting level, byte fields as unpadded base64url;
- the `prepared_sha256` fingerprint (recipient path: lowercase-hex SHA-256 of
  the canonical form with the `prepared_sha256` member omitted; passphrase
  path: SHA-256 of the domain tag `prepared_passphrase_seal_v1` followed by
  each item's `item_id` as ASCII);
- each `item_id` (lowercase-hex SHA-256 of that item's ciphertext);
- each deterministic upload idempotency key
  (`"seal1-" | "pwseal1-" + prepared_sha256[:32] + "-" + <item index>`);
- the canonical record bytes (`record_hex`) assembled from the prepared
  material with the listed `uris`, no `supersedes`, and no signer.

Determinism comes from the counter byte source declared in
`deterministic_rng`: byte `n` of the stream is `(start + n) mod 256`. The
recipient prepare consumes it in item order — content key, nonce, per-slot KEM
material, then the slot-shuffle draws — exactly as the sealed-PoE wrap draws
randomness; the passphrase prepare draws salt (16) then nonce (24) per item.
Recipient public keys are derived from the listed 32-byte seeds and pinned
alongside them.
