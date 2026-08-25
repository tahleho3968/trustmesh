# RFC 0007: JSON Schema claim validation

- **Status:** Proposed
- **Scope:** Validate credential subject claims against JSON Schema 2020-12
- **Depends on:** RFC 0002 (credential model), RFC 0005 (verifier pipeline)
- **Related:** issue #8

## Problem

Issuers can issue credentials with arbitrary subject claims. Without schema
validation, verifiers cannot enforce structural constraints on what claims are
present or their types — a credential with a missing or mistyped field passes
all existing stages.

## Proposal

### Typed `credentialSchema` on `Credential`

A new `credential_schema` field carries the W3C VC 2.0 `credentialSchema`
reference (id + type) alongside the credential. The schema content itself is
not embedded — verifiers supply it, matching the pattern established by
`StatusStage` (callers fetch and trust what they will).

### `SchemaStage` in the verifier pipeline

`SchemaStage::try_new(schema_ref, schema_json)` builds a `jsonschema::Validator`
at construction time. At check time:

- No `credentialSchema` → `Pass` (schemas are optional in W3C VC 2.0)
- Mismatched id or type → `Inconclusive` (verifier doesn't have the right schema)
- Subject claims don't validate → `Fail` with the first validation error
- All subjects pass → `Pass`

The stage validates each subject independently; multi-subject credentials
must all conform.

### Deliberate limitations

- **JSON Schema 2020-12 only.** Other schema formats (` ridden`, etc.) are
  out of scope. The `type` field in `credentialSchema` distinguishes formats.
- **No remote `$ref` resolution.** Schemas are supplied as complete documents.
  The `jsonschema` crate resolves local `$ref` references within the schema
  but does not fetch remote schemas (the `reqwest` feature is compiled but
  unused). Callers who need remote resolution can fetch and dereference
  themselves.
- **No schema inheritance or composition.** Each credential points at one
  schema; composed schemas must be resolved by the caller before passing
  to `SchemaStage`.

## Test strategy

Six unit tests covering: no schema (pass), conforming claims (pass), missing
required field (fail), additional properties (fail), mismatched schema ID
(inconclusive), and full pipeline composition with structural + proof + schema
+ trust policy stages.

## Alternatives considered

- **Fetching schemas by URL inside the library.** Rejected for the same reasons
  as status list fetching (RFC 0006): hidden network I/O, trust decisions
  the caller should make.
- **Embedding full JSON Schema in the credential.** Rejected: the W3C spec
  defines `credentialSchema` as a reference, not the content itself.
- **Validating at issuance time only.** Rejected: the verifier must independently
  check claims, not trust the issuer's self-certification.
