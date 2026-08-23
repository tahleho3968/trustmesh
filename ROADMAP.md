# TrustMesh Roadmap

TrustMesh is open infrastructure for issuing, holding, and verifying
W3C Verifiable Credentials 2.0 — designed so every layer is independently
useful and standards-conformant. This roadmap maps the full vision; each item
lands through a focused PR referencing an RFC or an issue.

## Where we are

| Layer | Crate | Status |
|---|---|---|
| Crypto core (Ed25519, Multikey, SHA-256) | `trustmesh-crypto` | ✅ shipped |
| Credential model (VC 2.0 structs, serde, validation) | `trustmesh-credentials` | ✅ shipped |
| Issuer (eddsa-jcs-2022 signing + verification) | `trustmesh-issuer` | ✅ shipped |
| Everything below | — | 🔜 see phases |

## Phase 1 — Trustworthy verification

The issuer can sign; the next question a relying party asks is *should I trust
this?*

- **Verifier engine pipeline** — structured verification: structural → proof →
  status → trust policy, with per-stage results (#TBD)
- **JCS conformance vectors** — RFC 8785 test suite wired into CI so
  canonicalization drift is impossible to merge (#TBD)
- **JSON Schema claim validation** — optional schema enforcement on subject
  claims at issuance and verification (#TBD)
- **Pluggable DID resolution** — trait-based resolver; `did:key` first,
  `did:web` next (#TBD)
- **Bitstring Status List** — encode/decode + status checks for revocation
  (#TBD)

## Phase 2 — Making it usable

Raw crates are for builders; these make TrustMesh operable.

- **CLI skeleton** (`trustmesh` binary) — keygen / issue / verify from the
  terminal (#TBD)
- **REST API** — axum service exposing issue/verify/status endpoints (#TBD)
- **Docker packaging** — one-command self-hosted verifier (#TBD)
- **QR code + static web verifier** — scan-to-verify without installing
  anything (#TBD)
- **End-to-end example** — university issues a diploma, holder presents,
  employer verifies (#TBD)

## Phase 3 — Holding & presenting

The other two corners of the triangle.

- **Verifiable Presentations** — model + signing/verification for VP 2.0
  (#TBD)
- **Wallet core** — storage, retrieval, consent-scoped sharing of credentials
  (#TBD)
- **Offline verification** — cached status lists and revocation windows
  (#TBD)

## Phase 4 — Ecosystem

- **Batch issuance & templates** — issue thousands of credentials from a
  template (#TBD)
- **PDF bridge** — embed/verify Data Integrity proofs in PDF/A documents
  (#TBD)
- **TypeScript SDK** — typed client over the REST API (#TBD)
- **Python SDK** — same surface for data-science/gov workflows (#TBD)
- **Threat model & security hardening** — published STRIDE analysis, fuzzing
  the parsers (#TBD)

## Principles (inherited from RFC 0001)

1. Standards first — W3C/IETF specs before invention.
2. Cryptography proves integrity; policy decides trust.
3. Small auditable crates; no kitchen-sink dependencies.
4. Every feature lands with tests, docs, and an RFC when it changes wire
   behavior.
