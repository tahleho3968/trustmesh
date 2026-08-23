# Security Policy

TrustMesh is trust infrastructure — security issues are treated with the highest priority.

## Supported versions

No releases exist yet. Security fixes will apply to the latest tagged release
and the default branch.

| Version              | Supported |
|----------------------|-----------|
| pre-release (`main`) | ✅        |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Use GitHub's **private vulnerability reporting**:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Include a description, reproduction steps, potential impact, and (if known)
   a suggested mitigation.

You will receive an acknowledgment within **72 hours**, and we will keep you
informed of progress toward a fix and coordinated disclosure.

## Scope

Of particular interest:

- Cryptographic implementation flaws (signature, key handling, randomness)
- Credential forgery or tampering vectors
- Privacy leaks (data exposure beyond what the holder consented to disclose)
- Replay / presentation-abuse attacks
- Supply-chain risks in dependencies and release artifacts

## Safe harbor

We consider good-faith security research to be a valuable contribution.
As long as you avoid privacy violations, data destruction, and service
degradation, we will not pursue action against researchers acting in good faith.

## Security best practices for adopters

- Never store issuer private keys unencrypted; prefer HSMs or OS keystores.
- Rotate signing keys and publish revocations promptly.
- Verifiers: always check signature, status, expiration, and your own trust policy.
- Holders: share only the claims a verifier actually needs.
