# TrustMesh

> **Open-source infrastructure for proving what is true, without revealing more than necessary.**

TrustMesh lets organizations issue cryptographically verifiable credentials — degrees,
licenses, employment records, certifications — and lets people prove claims about
themselves **without exposing more personal information than necessary**.

**Status:** 🚧 Early development (pre-release). The architecture and roadmap are being
established in the open. Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

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
   [Decentralized Identifiers](https://www.w3.org/TR/did-core/), and
   [OpenID4VCI / OpenID4VP](https://openid.net/sg/federation/) rather than inventing new formats.
2. **Identity ≠ Credential ≠ Trust.** TrustMesh provides cryptographic evidence; each verifier's
   trust policy decides which issuers it accepts.
3. **Privacy by design.** Minimum collection, minimum disclosure, minimum logging.
4. **Self-hostable.** Organizations must never be forced onto someone else's servers.
5. **No blockchain. No token. No proprietary cryptography.** Ever.

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| v0.1 | Crypto core, credential model, issuer + verifier, QR verify, CLI, Docker | 🔜 planned |
| v0.2 | Wallet, PDF signing/verification, templates, dashboards | |
| v0.3 | Selective disclosure, presentations, DID support, offline verification | |
| v0.4 | Integrations (university pilot), schema registry, webhooks, i18n | |
| v0.5+ | AI-agent & machine credentials, ZK proofs, cross-border verification | |

Detailed planning happens through issues and RFCs — see `docs/rfcs/` once established.

## Community

- 🐛 [Report a bug](.github/ISSUE_TEMPLATE/bug_report.yml)
- 💡 [Request a feature](.github/ISSUE_TEMPLATE/feature_request.yml)
- 🤝 [Contributing guide](CONTRIBUTING.md)
- 📜 [Code of Conduct](CODE_OF_CONDUCT.md)
- 🔒 [Security policy](SECURITY.md)

## License

Licensed under the [Apache License 2.0](LICENSE) — permissive, patent-friendly, and safe
for universities, governments, and companies to adopt.
