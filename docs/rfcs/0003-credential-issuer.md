# RFC 0003: Credential Issuer (`trustmesh-issuer`)

- **Status:** Accepted (implemented by `crates/trustmesh-issuer`)
- **Scope:** v0.1 issuance — signing credentials with Data Integrity proofs
- **Depends on:** RFC 0001 (`trustmesh-crypto`), RFC 0002 (`trustmesh-credentials`)
- **Related:** W3C [Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa/)
  (`eddsa-jcs-2022`), W3C [DID Method: `did:key`](https://w3c-ccg.github.io/did-method-key/)

## Goals

Turn a credential draft into a signed, standards-shaped Verifiable Credential,
and verify such credentials — the join point between the crypto core's Ed25519
keys and the credential model.

## Cryptosuite choice: `eddsa-jcs-2022`

The W3C EdDSA cryptosuite spec defines two suites. We implement
**`eddsa-jcs-2022`** (JSON Canonicalization Scheme, RFC 8785) rather than
`eddsa-rdfc-2022` (RDF Dataset Canonicalization):

- JCS is deterministic JSON — no RDF/JSON-LD expansion dependency.
- Credentials are pure JSON documents at this layer; RDF semantics add no value
  yet.
- The suite is standardized alongside `eddsa-rdfc-2022`, so nothing here is
  proprietary; adding the rdfc suite later is additive.

Canonicalization uses the `jcs-canonicalize` crate per the RFC 0001 dependency
policy (no hand-rolled canonicalization).

## Algorithm (per vc-di-eddsa §3.3, condensed)

Signing:

1. Validate the draft structurally; it must carry no existing proof.
2. `proofConfig = { type: "DataIntegrityProof", cryptosuite:
   "eddsa-jcs-2022", created, verificationMethod, proofPurpose }` plus the
   document's `@context` injected (context injection is normative).
3. `hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsecuredDocument))`.
4. `proofValue = "z" + base58btc(Ed25519.sign(hashData))`.

Verification mirrors steps 2–4 against the stored proof (minus `proofValue`),
resolving the public key from the proof's `verificationMethod`.

## Identity binding

- Keys are expressed as **`did:key`** of the Ed25519 Multikey from RFC 0001.
- `verificationMethod` is `did:key:<multikey>#<multikey>` (per did:key spec);
  verification re-derives the key from this field alone — no registry lookup.
- The issuer refuses to sign drafts whose `issuer` does not match its own
  `did:key`, eliminating issuer/key mis-binding by construction.

## API

```rust
let issuer = CredentialIssuer::new(SigningKey::generate()?);
let signed = issuer.issue(draft)?;              // created = now
let signed = issuer.issue_at(draft, created)?;  // deterministic (tests/replay)
verify_credential(&signed)? -> VerificationOutcome { structural, proof }
```

`issue_at` exists because Ed25519 proofs commit to `created`; reproducible
issuance requires pinning time explicitly.

## Non-goals for v0.1 (tracked as issues)

Batch issuance, key rotation/revocation metadata, HSM-backed signing,
multi-signature approval, `eddsa-rdfc-2022`, selective-disclosure suites
(BBS+), status-list signing (issuer signs status credentials later).

## Known limitations

- Only `assertionMethod` purpose is produced/accepted today.
- Verification trusts the key embedded in `verificationMethod`; binding that
  DID to a real-world institution is trust-policy work (RFC 0001 principle 2)
  and arrives with the verifier/trust layers.

## Test strategy

Round-trip issue→verify, tampered claim / tampered signature / wrong-key /
unsupported-suite negatives, issuer-mismatch refusal at signing, determinism
for fixed `created`, proof-shape conformance (type/cryptosuite/purpose/did:key),
JCS unit vectors (key ordering, ECMAScript number formatting), structural
validation integration.
