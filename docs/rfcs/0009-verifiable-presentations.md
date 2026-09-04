# RFC 0009: Verifiable Presentations

- **Status:** Proposed
- **Scope:** VP 2.0 model, signing, and verification
- **Depends on:** RFC 0001 (`trustmesh-crypto`), RFC 0002 (`trustmesh-credentials`), RFC 0003 (`trustmesh-issuer`)
- **Related:** W3C [Verifiable Credentials Data Model v2.0 § Verifiable Presentations](https://www.w3.org/TR/vc-data-model-2.0/#presentations-0)

## Problem

TrustMesh can issue and verify individual credentials, but has no way to
**present** multiple credentials as a single authenticated bundle. A holder
(e.g., a student) needs to wrap their diploma + transcript into a signed
presentation that an employer can verify in one step — confirming both that the
holder authorized the presentation and that each embedded credential is genuine.

## Proposal

### VP Model (`trustmesh-credentials`)

New `VerifiablePresentation` struct in `trustmesh-credentials/src/presentation.rs`:

```rust
pub struct VerifiablePresentation {
    pub context: Vec<Context>,
    pub types: Vec<String>,
    pub holder: Option<String>,              // did:key of the presentation signer
    pub verifiable_credential: Vec<Value>,   // embedded VCs (raw JSON)
    pub proof: Option<Proof>,
}
```

`PresentationBuilder` auto-inserts `BASE_CONTEXT` and
`"VerifiablePresentation"` type (mirrors `CredentialBuilder` pattern).

Validation: first `@context` is `BASE_CONTEXT`, type includes
`"VerifiablePresentation"`, at least one credential embedded.

### VP Signing (`trustmesh-issuer`)

New `PresentationHolder` in `trustmesh-issuer/src/presentation.rs`:

```rust
pub struct PresentationHolder {
    signing_key: SigningKey,
    verification_method: String,
}

impl PresentationHolder {
    pub fn new(signing_key: SigningKey) -> Self;
    pub fn did(&self) -> &str;
    pub fn sign(&self, presentation: VerifiablePresentation) -> Result<VerifiablePresentation, Error>;
    pub fn sign_at(&self, presentation: VerifiablePresentation, created: DateTime<Utc>) -> Result<VerifiablePresentation, Error>;
}
```

Algorithm (same as VC signing per RFC 0003, adapted for VP):

1. Validate the VP structurally; it must carry no existing proof.
2. Set `holder` to the signer's `did:key` if not already set.
3. `proofConfig = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022",
   created, verificationMethod, proofPurpose: "authentication" }` plus the
   document's `@context`.
4. `hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))`.
5. `proofValue = "z" + base58btc(Ed25519.sign(hashData))`.

Key difference from VC signing: `proofPurpose` is `"authentication"` (not
`"assertionMethod"`), indicating the holder is authenticating themselves, not
asserting the truth of the claims.

### VP Verification

New `verify_presentation()` in `trustmesh-issuer/src/presentation.rs`:

```rust
pub struct PresentationOutcome {
    pub structural: bool,
    pub proof: bool,
    pub credential_results: Vec<VerificationOutcome>,
}

pub fn verify_presentation(vp: &VerifiablePresentation) -> Result<PresentationOutcome, Error>;
pub fn verify_presentation_with(vp: &VerifiablePresentation, resolver: &dyn DidResolver) -> Result<PresentationOutcome, Error>;
```

Verification steps:

1. Structural check: `vp.validate()`.
2. VP proof check: same as VC proof verification but expects
   `proofPurpose: "authentication"`.
3. For each embedded credential in `verifiable_credential`: deserialize to
   `Credential` and run `verify_credential_with()`. Credentials that fail to
   deserialize are recorded as `{ structural: false, proof: false }`.

`valid()` = VP structural + VP proof + all credential proofs pass.

### CLI

New subcommands in `trustmesh-cli`:

```
trustmesh vp sign --key <KEY> --credentials <C1> <C2> ... --out <OUT>
trustmesh vp verify --presentation <FILE> --trusted <ISSUER_DID> ...
```

`vp sign` wraps one or more credential JSON files into a signed VP.
`vp verify` verifies the VP proof + each embedded credential.

### Reuse of existing infrastructure

- `Proof` struct is reused as-is (VP proofs use the same Data Integrity shape).
- `canonicalize()` from `trustmesh-issuer::canonical` is reused.
- `SigningKey` / `VerifyingKey` / `DidKeyResolver` are reused.
- No new dependencies required.

## Alternatives considered

1. **Generic `VerificationPipeline` for VPs** — The pipeline is designed for
   single credentials with composable stages. VP verification has a fundamentally
   different structure (verify container + iterate children). A dedicated
   `verify_presentation()` function is cleaner than forcing VPs into the pipeline.

2. **Separate `trustmesh-vp` crate** — VPs are small enough (model + sign +
   verify) to live in existing crates. Adding a 7th crate for ~200 lines of code
   isn't justified.

3. **DIDComm or out-of-band transport** — Out of scope. VPs are exchanged as
   plain JSON files / QR codes; transport is a caller concern.

## Non-goals

- Selective disclosure (BBS+) — future suite, tracked separately.
- VP chaining / nested presentations.
- DIDComm transport.
- Challenge/nonce binding (caller responsibility, not protocol-level).

## Test strategy

- Round-trip sign → verify with a single credential.
- Round-trip with multiple credentials.
- VP proof tampered → proof fails.
- Embedded credential tampered → credential proof fails, VP proof still passes.
- Wrong signing key → VP proof fails.
- Missing proof → error.
- Structural invalidity (no credentials, wrong type) → error.
- `proofPurpose` mismatch (assertionMethod instead of authentication) → error.
