# RFC 0005: Staged verifier pipeline

- **Status:** Proposed
- **Scope:** New `trustmesh-verifier` crate: composable verification stages with serializable per-stage results
- **Depends on:** RFC 0002 (credential model), RFC 0003 (`eddsa-jcs-2022` proof verification)
- **Related:** issue #6, issue #9 (pluggable DID resolution), issue #10 (Bitstring Status List)

## Problem

Verification today is a single function, `trustmesh_issuer::verify_credential`,
returning `(structural: bool, proof: bool)` — or an `Err`. Three problems:

1. **Inconsistent failure semantics.** A tampered claim yields
   `Ok(proof = false)`; a missing proof or unsupported cryptosuite yields
   `Err`. Callers must handle both channels and cannot tell *why* something
   failed.
2. **No room for the checks verifiers actually need.** Credential status
   (revocation) and issuer trust policy have no home; every future check would
   grow another ad-hoc boolean.
3. **Not auditable as a decision.** "Should I trust this credential?" produces
   two booleans, not a reviewable record of which checks ran and what they
   found.

## Proposal

A fourth crate, `trustmesh-verifier`, built around one trait:

```rust
pub trait VerificationStage: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict;
}
```

- **`Verdict`** is `Pass | Inconclusive(String) | Fail(String)`.
  `Inconclusive` exists so a stage can say "this credential carries
  information I cannot evaluate yet" without faking pass *or* fail — only
  `Fail` makes a result invalid.
- **`VerificationResult`** holds one serializable `StageOutcome`
  (`{ stage, verdict }`) per stage. `valid()` is *derived* from the outcomes,
  never stored, so a deserialized log can never contradict itself.
- **Every stage runs**, even after earlier failures: one pass returns the
  complete picture instead of the first error.
- **Built-in stages:** `StructuralStage`, `ProofStage` (delegates to
  `trustmesh_issuer::verify_credential`, mapping `Err` and
  `proof = false` onto `Fail` with reasons), `StatusStage` (validates
  `credentialStatus` shape; well-formed Bitstring entries are `Inconclusive`
  until #10 lands), and `TrustPolicyStage` (issuer allowlist).
- **Trust policy is opt-in.** `default_pipeline()` runs only objective checks
  (structural → proof → status); each deployment composes its own
  `TrustPolicyStage::allowing([…])`. Trust is policy, not cryptography, so no
  shipped default pretends to decide it for anyone.
- **`VerificationContext`** currently carries the credential; it grows
  additively (resolved DID documents #9, fetched status lists #10) via
  constructors.

The existing `trustmesh_issuer::verify_credential` API is unchanged; the
pipeline layers on top of it.

## Alternatives considered

- **Put the pipeline inside `trustmesh-issuer`.** Rejected: issuer and
  verifier are different roles with different trust positions; merging them
  breaks the small-single-purpose-crate principle and forces issuers to
  compile verification policy code.
- **Short-circuit on first failure.** Rejected: operators debugging rejected
  credentials need all failing checks at once, not one per retry cycle.
- **Boolean-only results.** Rejected: booleans cannot be logged into an audit
  trail or extended with new stages without breaking callers.
- **Deny-all default pipeline.** Rejected for the *default* constructor: it
  makes the happy path fail everywhere while looking like a bug. Deny-by-
  default remains the behavior *of TrustPolicyStage itself* (empty allowlist
  rejects everything).

## Non-goals

- Fetching and decoding Bitstring Status Lists (#10) — `StatusStage` reports
  `Inconclusive` until then rather than passing unrevoked-looking credentials.
- DID resolution beyond the embedded `did:key` verification method (#9).
- Temporal validity checking (validFrom/validUntil) — a future stage once the
  context carries evaluation time.
- Presentations (VP) verification (#16).

## Test strategy

Unit tests per stage (pass / fail / inconclusive paths), plus integration
tests asserting: independent multi-stage failure reporting, serialization
round-trips of results, deny-by-default trust policy, custom stage
composition, and end-to-end acceptance of a genuinely issued credential.
