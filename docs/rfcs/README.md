# RFCs — TrustMesh Design Process

Significant wire-format or architectural changes go through a lightweight RFC:
a numbered document under `docs/rfcs/` that records *what*, *why*, and the
rejected alternatives. Code reviews discuss implementation; RFCs settle design.

## When you need one

- Adding or changing a crate's public API in ways callers can observe
- Adopting a standard (which suite, which DID method, which status format)
- Introducing a new dependency
- Anything that changes bytes on the wire

You do **not** need one for bug fixes, tests, docs, CI, or internal refactors
with identical behavior.

## How to propose

1. Copy `_template.md` to `NNNN-short-name.md` using the next free number.
2. Status starts at `Proposed`; open a PR with the doc.
3. Discussion happens on the PR; update the doc rather than arguing only in
   comments.
4. On merge, flip status to `Accepted`. Superseded RFCs point to their
   successor and move to `Superseded`.

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-crypto-core.md) | Crypto core | Accepted |
| [0002](0002-credential-model.md) | Credential model | Accepted |
| [0003](0003-credential-issuer.md) | Credential issuer (`eddsa-jcs-2022`) | Accepted |
| [0004](0004-jcs-conformance.md) | JCS conformance vectors in CI | Proposed |
| [0005](0005-verifier-pipeline.md) | Staged verifier pipeline | Proposed |
| [0006](0006-bitstring-status-list.md) | Bitstring Status List checking | Proposed |
| [0007](0007-json-schema-validation.md) | JSON Schema claim validation | Proposed |
| [0008](0008-did-resolver.md) | Pluggable DID resolution | Proposed |
