# TrustMesh

[![CI](https://github.com/tahleho3968/trustmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/tahleho3968/trustmesh/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Open-source infrastructure for proving what is true, without revealing more than necessary.**

TrustMesh lets organizations issue cryptographically verifiable credentials — degrees,
licenses, employment records, certifications — and lets people prove claims about
themselves **without exposing more personal information than necessary**.

**Status:** 🚧 Early development (pre-release). Issuance and verification of W3C
Verifiable Credentials 2.0 with `eddsa-jcs-2022` Data Integrity proofs work today.
Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Try it

```console
$ cargo run -p trustmesh-issuer --example quickstart
structural: true, proof: true
{
  "@context": ["https://www.w3.org/ns/credentials/v2", ...],
  "type": ["VerifiableCredential", "ExampleAlumniCredential"],
  "issuer": "did:key:z6MkrZh...",
  "credentialSubject": { "alumniOf": "Example University", ... },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2Wkp6Rcy..."
  }
}
```

## What exists today

Four small, independently auditable crates:

| Crate | What it does |
|-------|--------------|
| [`trustmesh-crypto`](crates/trustmesh-crypto) | Ed25519 signing/verification, Multikey encoding, SHA-256 |
| [`trustmesh-credentials`](crates/trustmesh-credentials) | VC 2.0 data model with serde and structural validation |
| [`trustmesh-issuer`](crates/trustmesh-issuer) | Sign credentials (`eddsa-jcs-2022`), verify proofs |
| [`trustmesh-verifier`](crates/trustmesh-verifier) | Staged verification pipeline: structural → proof → status → trust policy |

```rust
use trustmesh_credentials::{Credential, Subject};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::{verify_credential, CredentialIssuer};

let issuer = CredentialIssuer::new(SigningKey::generate()?);

let draft = Credential::builder()
    .context("https://www.w3.org/ns/credentials/examples/v2")
    .credential_type("ExampleAlumniCredential")
    .issuer(issuer.did().to_owned())
    .subject(
        Subject::new()
            .with_id("did:example:graduate-1")
            .with_claim("alumniOf", serde_json::json!("Example University")),
    )
    .build()?;

let signed = issuer.issue(draft)?;
let outcome = verify_credential(&signed)?;   // structural + proof verdicts
assert!(outcome.proof);
```

Signatures follow [vc-di-eddsa `eddsa-jcs-2022`](https://www.w3.org/TR/vc-di-eddsa/)
(JCS / RFC 8785 canonicalization) with `did:key` verification methods.

## The vision

```text
University ──▶ Issue credential ──▶ Holder wallet ──▶ Selective disclosure ──▶ Employer
                                                                            │
                                                                       ✓ VERIFIED
```

A graduate proves *"I hold a bachelor's degree"* to an employer. The employer verifies the
issuer's signature, the credential status, and nothing else. No address. No date of birth.
No transcript. No phone-home to a centralized verification company.

TrustMesh is being built as a **modular trust infrastructure platform**:

- **Issuers** (universities, governments, employers) issue standards-based verifiable credentials.
- **Holders** store credentials in their own wallet and control exactly what is disclosed.
- **Verifiers** check cryptographic proof + status under their own trust policies.

## Principles

1. **Standards first.** Build on [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
   [Data Integrity](https://www.w3.org/TR/vc-data-integrity/), [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/),
   and [Decentralized Identifiers](https://www.w3.org/TR/did-core/) rather than inventing new formats.
2. **Identity ≠ Credential ≠ Trust.** TrustMesh provides cryptographic evidence; each verifier's
   trust policy decides which issuers it accepts.
3. **Privacy by design.** Minimum collection, minimum disclosure, minimum logging.
4. **Self-hostable.** Organizations must never be forced onto someone else's servers.
5. **No blockchain. No token. No proprietary cryptography.** Ever.

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| Shipped | Crypto core · credential model · issuer + proof verification | ✅ |
| 1 — Verification | Staged verifier pipeline · JCS conformance vectors · JSON Schema validation · pluggable DIDs · Bitstring Status List | [#6–#10](https://github.com/tahleho3968/trustmesh/issues) |
| 2 — Usability | CLI · REST API · Docker · QR web verifier · end-to-end example | #11–#15 |
| 3 — Holding | Presentations · wallet core · offline verification | #16–#18 |
| 4 — Ecosystem | Batch issuance · PDF bridge · TS & Python SDKs · threat model | #19–#23 |

Design decisions are recorded as lightweight RFCs in [`docs/rfcs/`](docs/rfcs/README.md).
Full details in [ROADMAP.md](ROADMAP.md).

## Related work

Prior art in this space includes SpruceID's [`ssi`](https://github.com/spruceid/ssi) and
DIDKit. TrustMesh takes a different slice: small single-purpose crates with strict
dependency vetting, built for auditability first.

## Community

- 🐛 [Report a bug](.github/ISSUE_TEMPLATE/bug_report.yml)
- 💡 [Request a feature](.github/ISSUE_TEMPLATE/feature_request.yml)
- 🤝 [Contributing guide](CONTRIBUTING.md)
- 📜 [Code of Conduct](CODE_OF_CONDUCT.md)
- 🔒 [Security policy](SECURITY.md)
- 🗺️ [Roadmap](ROADMAP.md)

Good starting points: issues labeled [`good first issue`](https://github.com/tahleho3968/trustmesh/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

## License

Licensed under the [Apache License 2.0](LICENSE) — permissive, patent-friendly, and safe
for universities, governments, and companies to adopt.
