# RFC 0006: Bitstring Status List checking

- **Status:** Proposed
- **Scope:** Decode and check W3C Bitstring Status Lists; real revocation verdicts in the pipeline
- **Depends on:** RFC 0002 (credential model), RFC 0005 (verifier pipeline)
- **Related:** issue #10, [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)

## Problem

The verifier pipeline's status stage cannot evaluate a well-formed
`credentialStatus` entry: it reports `Inconclusive`, so no deployment can
honor revocations. Checking requires decoding `encodedList` — multibase
base64url-no-padding of a GZIP-compressed bitstring — which in turn requires
two new dependencies (base64, GZIP).

## Proposal

### Codec in `trustmesh-credentials`

`status.rs` grows the pure data-model side; no network I/O lives here:

- `BitstringStatusList` — the parsed subject of a fetched
  `BitstringStatusListCredential`, constructed via `from_credential` (which
  validates the enclosing credential's `type` includes
  `BitstringStatusListCredential`) or `from_parts`.
- `expand()` implements the specification's Bitstring Expansion Algorithm:
  multibase (`u` prefix required) → base64url-no-pad decode → GZIP
  decompress → reject bitstrings under the 16 KB minimum
  (`STATUS_LIST_LENGTH_ERROR` semantics), preserving herd privacy.
- `ExpandedStatusList::check(entry)` applies the validate algorithm: purpose
  match between entry and list, base-10 `statusListIndex` parsing, range
  check (`RANGE_ERROR`), then bit semantics. Index *i* maps to byte *i*/8,
  mask `0x80 >> (*i* mod 8)` — most-significant-bit first within each byte,
  confirmed against the reference implementation's `leftToRightIndexing`
  default.
- `compress_bitstring(bytes)` gives issuers (and tests) the encode direction;
  it refuses sub-minimum inputs.
- Errors are a dedicated `StatusError` whose variants mirror the spec's
  processing-error taxonomy.

### Pipeline integration in `trustmesh-verifier`

Fetching a status list is an I/O and trust decision (which URLs to contact,
whether to trust its issuer, how fresh it must be) — deliberately outside
these crates. Callers fetch, verify the list credential's proof themselves,
and supply it on the context:

```rust
let ctx = VerificationContext::new(&credential)
    .with_status_list(BitstringStatusList::from_credential(&fetched)?);
let result = pipeline.verify_with(&ctx);
```

`StatusStage` then reports real verdicts: bit unset → `Pass`; set with
`revocation` purpose → `Fail("credential has been revoked")`; set with
`suspension` → `Fail`. A supplied list that fails to expand or mismatches
the entry fails loudly. An entry pointing at an unsupplied URL stays
`Inconclusive` — never a silent pass. `verify()` keeps its existing shape;
`verify_with(&ctx)` is additive.

### Deliberate limitations

- **Single-bit entries only.** Permitted by the conformance clause
  ("processors MAY choose to only support bitstring entry sizes of 1");
  `statusSize ≠ 1` on either entry or list produces an explicit error rather
  than a misread. Multi-bit `message` lists are future work.
- **Purposes:** `revocation` and `suspension` carry verdict semantics;
  other purposes fail as unsupported rather than guessing.

## Alternatives considered

- **Fetching inside the library.** Rejected: hidden network I/O violates
  self-hostability expectations and makes trust decisions (issuer of the
  list may differ from issuer of the credential!) silently for the caller.
  The spec explicitly warns these issuers might differ.
- **Support every multibase encoding.** Rejected for now: the v1.0
  recommendation requires base64url-no-padding with the `u` multibase prefix;
  accepting more invites ambiguity. Revisit if ecosystems diverge.
- **Return booleans from `check`.** Rejected: callers need to distinguish
  active / revoked / suspended / malformed; `Verdict` strings feed audit
  logs.
- **Hand-rolled inflate.** Rejected; `flate2`'s default backend
  (`miniz_oxide`) is pure Rust, widely audited, and dependency-vetted here
  once.

## Non-goals

- Network retrieval, caching, and staleness policy (#12 REST API, #18
  offline verification).
- Publishing/issuing status lists (batch issuance #19).
- Multi-bit status messages (`statusSize > 1`, `statusMessage` mapping).
- Presentations carrying status (#16).

## Test strategy

Known-answer vector taken verbatim from the W3C recommendation (Example 3's
`encodedList` expands to exactly 16,384 zero bytes); explicit MSB-first
bit-order tests at index 0, 7, and 131,071; round-trip through
`compress_bitstring` across all four byte boundaries; rejection paths for
undersized lists, corrupt GZIP, wrong multibase prefix, non-numeric indexes,
purpose mismatch, range overflow, and multi-bit sizes; pipeline tests proving revoked credentials fail, active ones pass, unsupplied lists stay
`Inconclusive`, and unrelated supplied lists do not satisfy an entry.
