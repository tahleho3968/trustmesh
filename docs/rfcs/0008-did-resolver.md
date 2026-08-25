# RFC 0008: Pluggable DID resolution

- **Status:** Proposed
- **Scope:** Trait-based DID resolver with `did:key` and `did:web` implementations
- **Depends on:** RFC 0002 (credential model), RFC 0005 (verifier pipeline)
- **Related:** issue #9

## Problem

The verifier resolves DIDs via inline string parsing in `trustmesh-issuer`.
Only `did:key` is supported. To verify credentials from issuers using
`did:web` (or other methods), the verifier must fetch and parse DID documents
— but there is no abstraction for this, and no way to plug in custom resolvers.

## Proposal

### `DidResolver` trait in `trustmesh-crypto`

A synchronous trait that maps a DID (or `verificationMethod` URL) to a
`VerifyingKey`. All resolution is sync — callers pre-fetch DID documents
out-of-band and supply them to the resolver, matching the pattern established
by status lists (RFC 0006).

```rust
pub trait DidResolver: Send + Sync {
    fn supported_methods(&self) -> &[&str];
    fn resolve(&self, did: &str) -> Result<VerifyingKey, DidError>;
}
```

### Built-in resolvers

- **`DidKeyResolver`** — decodes `did:key` DIDs by extracting the embedded
  Multikey-encoded public key. Self-certifying; no external data needed.
- **`DidWebResolver`** — resolves `did:web` DIDs using pre-fetched DID
  documents. Callers supply a `HashMap<String, Value>` of DID → document.
  Extracts `publicKeyMultibase` from `Ed25519VerificationKey2020` verification
  methods. Supports fragment targeting (e.g., `did:web:example.com#key-1`).
- **`CompositeResolver`** — delegates to method-specific resolvers based on
  the DID method prefix.

### Pipeline integration

`ProofStage` holds a `Box<dyn DidResolver>` (default: `DidKeyResolver`).
Callers supply a custom resolver via `ProofStage::with_resolver`. The resolver
is threaded through to `verify_credential_with` in `trustmesh-issuer`, replacing
the inline `verifying_key_from_method` function.

### Deliberate limitations

- **Sync only.** Async resolution would require making the entire pipeline
  async, which is a disproportionate change. Callers who need `did:web`
  resolution fetch DID documents before verification.
- **Ed25519 keys only.** The `Ed25519VerificationKey2020` type is the only
  supported key type in `DidWebResolver`. Other types fail explicitly.
- **No DID document validation.** The resolver trusts the caller's pre-fetched
  document. It does not verify the DID document's own proof or check that the
  controller matches. This is the caller's responsibility.

## Test strategy

`DidKeyResolver`: resolves full verification method URLs and bare DIDs,
rejects non-key methods and invalid multikeys. `DidWebResolver`: resolves
with and without fragments, rejects missing documents, unknown fragments,
and unsupported key types. `CompositeResolver`: delegates to the correct
resolver, rejects unsupported methods. Pipeline: `ProofStage::with_resolver`
accepts a `CompositeResolver` and verifies a credential end-to-end.

## Alternatives considered

- **Async trait.** Rejected: would require `async fn` in `VerificationStage`,
  propagating `async` through the entire pipeline and all call sites. The
  sync + pre-fetch pattern is simpler and consistent with status lists.
- **Resolver in `trustmesh-issuer` only.** Rejected: the issuer crate should
  not depend on resolver infrastructure — it only needs the trait, not the
  implementations. Placing the trait in `trustmesh-crypto` (which defines
  `VerifyingKey`) keeps the dependency graph clean.
- **DID document validation inside the resolver.** Rejected: DID document
  proofs use different cryptosuites (e.g., `JsonWebSignature2020`) that are
  out of scope. Validation is the caller's responsibility.
