# RFC 0004: JCS conformance vectors in CI

- **Status:** Proposed
- **Scope:** Pin credential canonicalization to the official RFC 8785 test suite
- **Depends on:** RFC 0003 (`eddsa-jcs-2022` issuer)
- **Related:** [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), issue #7,
  [cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization) test data

## Problem

`eddsa-jcs-2022` signs the output of JCS canonicalization, so every byte of
every signature depends on `canonicalize()` behaving exactly per RFC 8785.
Today that function is a thin wrapper over `serde_jcs`, guarded only by three
hand-written unit tests. Two failure modes are unprotected:

1. **Dependency drift.** A `serde_jcs` or `serde_json` upgrade can change
   number formatting or key ordering; nothing fails until an interop partner
   (or production verifier) rejects our signatures.
2. **Silent replacement.** Nothing stops a future refactor from swapping the
   serializer for one that sorts by Unicode scalar value instead of UTF-16
   code units — a difference invisible in ASCII tests but signature-breaking
   for any credential with astral-plane claim names.

## Proposal

Vendor the official conformance vectors into
`crates/trustmesh-issuer/tests/vectors/rfc8785/` (input/output pairs:
`arrays`, `french`, `structures`, `unicode`, `values`, `weird`; Apache-2.0,
same as TrustMesh) with a provenance README recording source revision.

Add an integration test, `crates/trustmesh-issuer/tests/jcs_conformance.rs`,
which runs on every `cargo test` (and therefore in CI):

1. **Byte-for-byte** — each input document must canonicalize to exactly the
   expected bytes, covering key ordering (including UTF-16 code-unit order),
   string escaping, whitespace stripping, and ES6 number serialization
   (`1e+30`, `333333333.3333333`).
2. **Idempotence** — canonicalizing canonical output is a no-op.
3. **Explicit UTF-16 sort rule** — a named test documenting that astral-plane
   keys sort before certain BMP keys, so the rule survives even if vectors are
   ever trimmed.
4. **End-to-end binding** — issue and verify a credential whose claims carry
   the same edge cases (euro sign, emoji, Hebrew letter, `</script>`,
   `1e+30`, `0.002`) to prove the signed path uses the conformant
   canonicalizer.

Because these run under the existing `cargo test --workspace` CI job, no
pipeline changes are needed.

## Alternatives considered

- **Fetch vectors at test time from GitHub.** Rejected: CI must not depend on
  network availability or upstream repository mutability, and vendoring pins
  the exact revision under audit.
- **Generate ES6 number torture inputs locally** (the `es6testfile100m`
  algorithm). Deferred: valuable for a dedicated number-formatting
  implementation, but we delegate number formatting to `serde_jcs`; the six
  official files already include its known hard cases. Revisit if we ever
  write our own serializer (see non-goals).
- **Property-based fuzzing of canonicalization.** Deferred to the Phase 4
  fuzzing work (#23); conformance vectors catch spec drift, fuzzing catches
  crashes — different targets.

## Non-goals

- Replacing `serde_jcs` with an in-house canonicalizer (only justified if the
  vectors expose a defect).
- `eddsa-rdfc-2022` / RDF canonicalization support (#6 pipeline tracks suites).
- Verifier-side trust policy — out of scope here, tracked by #6/#9.

## Test strategy

The proposal *is* a test strategy: `cargo test -p trustmesh-issuer` runs the
conformance suite locally and in CI. Acceptance: all six vector pairs pass
byte-for-byte, idempotence holds, and the stress credential verifies.
