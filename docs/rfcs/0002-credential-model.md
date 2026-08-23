# RFC 0002: Credential Model (`trustmesh-credentials`)

- **Status:** Accepted (implemented by `crates/trustmesh-credentials`)
- **Scope:** v0.1 credential data model
- **Depends on:** RFC 0001 (crypto core stays independent of this crate; the
  issuer crate will join them)
- **Related:** W3C [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
  [Data Integrity](https://www.w3.org/TR/vc-data-integrity/),
  [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)

## Goals

Typed Rust representation of W3C Verifiable Credentials 2.0 with JSON
serialization that round-trips spec-shaped documents losslessly, plus the
structural validation verifiers need before any cryptographic checking.

## Spec ↔ Rust mapping

| W3C term | Rust | Notes |
|----------|------|-------|
| `@context` | `Vec<Context>` | ordered; `Context::Url` / `Context::Object`; entry 0 must be `…/ns/credentials/v2` |
| `type` | `Vec<String>` | must include `"VerifiableCredential"` |
| `issuer` | `Issuer` enum | untagged URI string or `{ "id": … }` object |
| `validFrom` / `validUntil` | `Option<DateTime<Utc>>` | RFC 3339; serialized with `Z`, offsets normalized to UTC |
| `credentialSubject` | `Vec<Subject>` | one struct per subject; `id` + flattened open claims map |
| `credentialStatus` | `Option<serde_json::Value>` | open by design; `bitstring_status()` typed accessor for Bitstring Status List entries |
| `proof` | `Option<Proof>` | Data Integrity shape; unknown proof params captured in `details` |
| *(anything else)* | `extensions: Map<String, Value>` | flattened catch-all so unrecognized extension terms survive a round-trip |

Field names serialize in camelCase exactly as the spec requires (`validFrom`,
`credentialSubject`, …).

## Design decisions

1. **Open-world extensibility over exhaustive typing.** Unknown members are
   captured and re-emitted, never rejected — required by JSON-LD-based specs.
   Known hot paths (`BitstringStatusListEntry`) get typed accessors.
2. **Validation is structural only** (`validate()`): base context/type present,
   ≥ 1 subject, `validFrom ≤ validUntil`. Trust decisions and signature checks
   live elsewhere.
3. **Builder enforces the same invariants**, so credentials built through it
   are valid by construction; deserialized ones are checked explicitly.
4. **Datetimes normalize to UTC.** Semantically equal instants compare equal;
   sub-second precision is preserved via `SecondsFormat::AutoSi`.
5. **No URI grammar enforcement yet** (RFC 3986 validation deferred); values
   are opaque strings at this layer.

## Non-goals

- Proof generation/verification (issuer crate, next).
- Status list bitstring decoding (verifier side, later).
- JSON-LD expansion/framing.
- Selective disclosure / BBS+.

## Known limitations

- serde's `flatten` routes integers > 2^53 through f64 buffering inside
  `Subject.claims` / `Proof.details`; irrelevant to current suites but worth
  revisiting if large integers ever appear in extensions.
- `credentialStatus` shapes other than Bitstring Status List entries are
  carried as raw `Value`.

## Test strategy

Spec example round-trip (semantic JSON equality), field-name conformance,
builder defaults + failure modes, all four structural validation errors,
datetime `Z` formatting and offset parsing, status-entry typed accessor,
proof round-trip including `details`.
