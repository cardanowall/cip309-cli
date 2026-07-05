# Prepared-seal cross-SDK parity vectors

Canonical vectors for the SDK-level portable `prepared_seal_json_v1`
artifact and its derivations. These files are byte-identical mirrors of
the vectors the Rust and Python SDKs pin; any edit must be mirrored to
those copies in lockstep.

Each vector pins, for a fully deterministic `sealPrepare` run:

- the exact `prepared_seal_json_v1` serialization (`prepared_seal_json`) —
  compact UTF-8 JSON, keys sorted lexicographically by byte order at every
  nesting level, byte fields as unpadded base64url;
- the `prepared_sha256` fingerprint (lowercase-hex SHA-256 of the canonical
  form with the `prepared_sha256` member omitted);
- each `item_id` (lowercase-hex SHA-256 of that item's ciphertext);
- each deterministic upload idempotency key
  (`"seal1-" + prepared_sha256[..32] + "-" + <item index>`);
- the canonical record bytes (`record_hex`) assembled from the prepared
  material with the listed `uris`, no `supersedes`, and no signer.

Determinism comes from the counter byte source declared in
`deterministic_rng`: byte `n` of the stream is `(start + n) mod 256`. The
prepare consumes it in item order — content key, nonce, per-slot KEM
material, then the slot-shuffle draws — exactly as the sealed-PoE wrap
draws randomness. Recipient public keys are derived from the listed
32-byte seeds and pinned alongside them.
