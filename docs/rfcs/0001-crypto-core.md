# RFC 0001: TrustMesh Crypto Core

- **Status:** Accepted (implemented by `crates/trustmesh-crypto`)
- **Scope:** v0.1 cryptographic foundation
- **Related:** README roadmap v0.1; W3C [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/), [Data Integrity](https://www.w3.org/TR/vc-data-integrity/)

## Goals

Provide the minimal, audited-crate-backed primitive layer every later TrustMesh
component (issuer, verifier, wallet, status lists) builds on:

1. Ed25519 signing and verification (FIPS 186-5).
2. Public-key interchange in the Data Integrity ecosystem format:
   **Multikey** — multicodec `0xed 0x01` prefix, multibase base58btc (`z…`).
3. SHA-256 digests (required by Data Integrity cryptosuites and Bitstring
   Status List).

## Non-goals for v0.1

- BBS+ / selective disclosure (v0.3+).
- DID resolution.
- Any hash-to-curve, VRF, or zero-knowledge machinery.
- Hand-rolled cryptography of any kind.

## Dependency policy

Crypto-relevant behavior comes exclusively from vetted crates:

| Crate | Role |
|-------|------|
| `ed25519-dalek` 2.x | signatures, key handling (`zeroize` on secrets) |
| `sha2` | SHA-256 |
| `bs58` | base58btc encoding (an encoding, not crypto) |
| `getrandom` | OS entropy |

No `unsafe` is permitted in workspace code (`[workspace.lints] unsafe_code = "forbid"`).
CI enforces `cargo clippy -D warnings`, `cargo fmt --check`, `cargo test`.

## API surface

```rust
SigningKey::generate() -> Result<SigningKey>      // OS entropy
SigningKey::from_bytes(&[u8; 32]) -> SigningKey
signing_key.verifying_key() -> VerifyingKey
signing_key.sign(message) -> Signature            // deterministic Ed25519
verifying_key.verify(message, &signature) -> Result<()>
verifying_key.multikey() -> String                // "z6Mk…" form
VerifyingKey::from_multikey(&str) -> Result<VerifyingKey>
sha256(data) -> [u8; 32]
```

Design notes:

- Secret material never implements leaky `Debug`; rendering is `[redacted]`
  and covered by a regression test.
- Errors are a single flat enum (`Error`) — this crate has exactly four
  failure modes and callers shouldn't need to match deeper.
- No serde yet: serialization belongs to the credential-model crate.

## Test strategy

Known-vector tests (RFC 8032 seed vector, FIPS 180 SHA-256 "abc"), round-trip
property tests (multikey encode/decode, sign/verify), negative tests (tampered
message, wrong key, malformed Multikey prefix/base58/prefix-bytes), determinism
test (same seed + message → same signature), entropy test, redaction test.

## Alternatives considered

- **P-256 / ES256 first** — needed eventually for platform wallet keystores,
  but adds ECDSA nonce-handling risk surface now. Deferred to v0.2.
- **`multibase`/`multihash` crates** — effectively unmaintained; the Multikey
  surface we need is ~20 lines over `bs58` with strict validation, which we can
  test exhaustively.
- **Injectable RNG parameter** — rejected for v0.1: trait-version churn between
  rand 0.8/0.9 ecosystems; tests use fixed seeds because Ed25519 signing is
  deterministic, so no RNG injection is needed for reproducible tests.
