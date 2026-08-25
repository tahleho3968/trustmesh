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
| Verifier pipeline (structural → proof → status → trust policy) | `trustmesh-verifier` | ✅ shipped |
| Everything below | — | 🔜 see phases |

## Phase 1 — Trustworthy verification

The issuer can sign; the next question a relying party asks is *should I trust
this?*

- **Verifier engine pipeline** — structured verification: structural → proof →
  status → trust policy, with per-stage results (#6) ✅
- **JCS conformance vectors** — RFC 8785 test suite wired into CI so
  canonicalization drift is impossible to merge (#7)
- **JSON Schema claim validation** — optional schema enforcement on subject
  claims at issuance and verification (#8)
- **Pluggable DID resolution** — trait-based resolver; `did:key` first,
  `did:web` next (#9)
- **Bitstring Status List** — encode/decode + status checks for revocation
  (#10)

## Phase 2 — Making it usable

Raw crates are for builders; these make TrustMesh operable.

- **CLI skeleton** (`trustmesh` binary) — keygen / issue / verify from the
  terminal (#11)
- **REST API** — axum service exposing issue/verify/status endpoints (#12)
- **Docker packaging** — one-command self-hosted verifier (#13)
- **QR code + static web verifier** — scan-to-verify without installing
  anything (#14)
- **End-to-end example** — university issues a diploma, holder presents,
  employer verifies (#15)

## Phase 3 — Holding & presenting

The other two corners of the triangle.

- **Verifiable Presentations** — model + signing/verification for VP 2.0
  (#16)
- **Wallet core** — storage, retrieval, consent-scoped sharing of credentials
  (#17)
- **Offline verification** — cached status lists and revocation windows
  (#18)

## Phase 4 — Ecosystem

- **Batch issuance & templates** — issue thousands of credentials from a
  template (#19)
- **PDF bridge** — embed/verify Data Integrity proofs in PDF/A documents
  (#20)
- **TypeScript SDK** — typed client over the REST API (#21)
- **Python SDK** — same surface for data-science/gov workflows (#22)
- **Threat model & security hardening** — published STRIDE analysis, fuzzing
  the parsers (#23)

## Principles (inherited from RFC 0001)

1. Standards first — W3C/IETF specs before invention.
2. Cryptography proves integrity; policy decides trust.
3. Small auditable crates; no kitchen-sink dependencies.
4. Every feature lands with tests, docs, and an RFC when it changes wire
   behavior.
