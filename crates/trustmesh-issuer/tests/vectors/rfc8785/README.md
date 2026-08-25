# RFC 8785 (JCS) conformance vectors

Official test data for the JSON Canonicalization Scheme, vendored from
<https://github.com/cyberphone/json-canonicalization> — the repository cited as
the source of conformance data by [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785).

- `input/` — non-canonicalized documents
- `output/` — expected canonical form of each same-named input file

Each pair is exercised byte-for-byte by `tests/jcs_conformance.rs`.

## Provenance

- Downloaded: 2026-08-25
- Source revision: `master`, `testdata/input` tree `425eb50d3011b88c7066f65aa1d86d48e05d71e1`,
  `testdata/output` tree `4a2e3ed40280aebbee9e5911f6c7f0ee699ee62b`
- © 2018 Anders Rundgren, licensed under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
  (same license as TrustMesh)

## Refreshing

Re-download both directories from upstream and update this file. Any change to
the vectors that breaks our canonicalizer is a conformance regression and must
be investigated before merging.
