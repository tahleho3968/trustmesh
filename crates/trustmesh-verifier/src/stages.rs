use std::collections::HashSet;

use trustmesh_credentials::BITSTRING_STATUS_LIST_ENTRY_TYPE;
use trustmesh_issuer::verify_credential;

use crate::pipeline::{Verdict, VerificationContext, VerificationStage};

/// Runs the credential's own structural validation (required contexts, types,
/// subjects, validity ordering).
pub struct StructuralStage;

impl VerificationStage for StructuralStage {
    fn name(&self) -> &'static str {
        "structural"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        match ctx.credential().validate() {
            Ok(()) => Verdict::Pass,
            Err(error) => Verdict::Fail(error.to_string()),
        }
    }
}

/// Verifies the `eddsa-jcs-2022` Data Integrity proof by delegating to
/// `trustmesh-issuer`. Cryptosuite and proof-purpose mismatches surface as
/// failures with the underlying reason.
pub struct ProofStage;

impl VerificationStage for ProofStage {
    fn name(&self) -> &'static str {
        "proof"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        match verify_credential(ctx.credential()) {
            Ok(outcome) if outcome.proof => Verdict::Pass,
            Ok(_) => Verdict::Fail("cryptographic proof verification failed".into()),
            Err(error) => Verdict::Fail(error.to_string()),
        }
    }
}

/// Validates the shape of any `credentialStatus` entry. Revocation checking
/// itself arrives with Bitstring Status List support (#10): a well-formed
/// entry is reported as [`Verdict::Inconclusive`] rather than silently
/// passing as unrevoked.
pub struct StatusStage;

impl VerificationStage for StatusStage {
    fn name(&self) -> &'static str {
        "status"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        match ctx.credential().bitstring_status() {
            Ok(None) => Verdict::Pass,
            Ok(Some(entry)) if entry.status_type == BITSTRING_STATUS_LIST_ENTRY_TYPE => {
                Verdict::Inconclusive(
                    "Bitstring Status List revocation checking is not implemented yet (#10)".into(),
                )
            }
            Ok(Some(entry)) => Verdict::Fail(format!(
                "unsupported credentialStatus type: {}",
                entry.status_type
            )),
            Err(error) => Verdict::Fail(format!("malformed credentialStatus: {error}")),
        }
    }
}

/// Checks the credential issuer against a caller-supplied allowlist.
///
/// **Deny by default:** an empty allowlist rejects every credential. Trust is
/// a policy decision, not a cryptographic fact, so nothing passes until this
/// verifier's operator says who it trusts.
pub struct TrustPolicyStage {
    allowed_issuers: HashSet<String>,
}

impl TrustPolicyStage {
    pub fn allowing<I, S>(allowed_issuers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_issuers: allowed_issuers.into_iter().map(Into::into).collect(),
        }
    }
}

impl VerificationStage for TrustPolicyStage {
    fn name(&self) -> &'static str {
        "trust_policy"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        let issuer = ctx.credential().issuer.id();
        if self.allowed_issuers.contains(issuer) {
            Verdict::Pass
        } else {
            Verdict::Fail(format!(
                "issuer {issuer} is not accepted by this verifier's trust policy"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use trustmesh_credentials::{Credential, Subject};
    use trustmesh_crypto::SigningKey;
    use trustmesh_issuer::CredentialIssuer;

    use super::*;

    const CREATED: fn() -> chrono::DateTime<chrono::Utc> =
        || chrono::Utc.with_ymd_and_hms(2026, 8, 25, 12, 0, 0).unwrap();

    fn signed_credential() -> (CredentialIssuer, Credential) {
        let issuer = CredentialIssuer::new(SigningKey::from_bytes(&[9u8; 32]));
        let draft = Credential::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer(issuer.did().to_owned())
            .subject(
                Subject::new()
                    .with_id("did:example:graduate-1")
                    .with_claim("alumniOf", serde_json::json!("Example University")),
            )
            .build()
            .expect("valid draft");
        let signed = issuer.issue_at(draft, CREATED()).expect("issues");
        (issuer, signed)
    }

    #[test]
    fn structural_passes_signed_and_rejects_broken() {
        let (_, credential) = signed_credential();
        let ctx = VerificationContext::new(&credential);
        assert_eq!(StructuralStage.check(&ctx), Verdict::Pass);

        let mut broken = credential.clone();
        broken.credential_subject.clear();
        let ctx = VerificationContext::new(&broken);
        assert!(matches!(StructuralStage.check(&ctx), Verdict::Fail(_)));
    }

    #[test]
    fn proof_passes_genuine_and_rejects_tampered_or_unsigned() {
        let (issuer, mut credential) = signed_credential();

        let ctx = VerificationContext::new(&credential);
        assert_eq!(ProofStage.check(&ctx), Verdict::Pass);

        credential.credential_subject[0]
            .claims
            .insert("alumniOf".into(), serde_json::json!("Fake University"));
        let ctx = VerificationContext::new(&credential);
        assert!(matches!(ProofStage.check(&ctx), Verdict::Fail(_)));

        let unsigned = Credential::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer(issuer.did().to_owned())
            .subject(Subject::new())
            .build()
            .unwrap();
        let ctx = VerificationContext::new(&unsigned);
        assert!(
            matches!(ProofStage.check(&ctx), Verdict::Fail(reason) if reason.contains("no proof"))
        );
    }

    #[test]
    fn status_passes_without_entry_flags_malformed_and_marks_wellformed_inconclusive() {
        let (_, credential) = signed_credential();
        let mut no_status = credential.clone();
        assert!(matches!(
            StatusStage.check(&VerificationContext::new(&no_status)),
            Verdict::Pass
        ));

        no_status.credential_status = Some(serde_json::json!({"statusListIndex": "94567"}));
        assert!(matches!(
            StatusStage.check(&VerificationContext::new(&no_status)),
            Verdict::Fail(reason) if reason.contains("malformed")
        ));

        let mut with_status = credential;
        with_status.credential_status = Some(
            serde_json::to_value(trustmesh_credentials::StatusListEntry::bitstring(
                "https://university.example/status/3#94567",
                "revocation",
                "94567",
                "https://university.example/status/3",
            ))
            .unwrap(),
        );
        assert_eq!(
            StatusStage.check(&VerificationContext::new(&with_status)),
            Verdict::Inconclusive(
                "Bitstring Status List revocation checking is not implemented yet (#10)".into()
            )
        );
    }

    #[test]
    fn trust_policy_denies_by_default_and_accepts_listed_issuers() {
        let (issuer, credential) = signed_credential();

        let deny_all = TrustPolicyStage::allowing([] as [&str; 0]);
        assert!(matches!(
            deny_all.check(&VerificationContext::new(&credential)),
            Verdict::Fail(reason) if reason.contains(issuer.did())
        ));

        let trusting = TrustPolicyStage::allowing([issuer.did()]);
        assert_eq!(
            trusting.check(&VerificationContext::new(&credential)),
            Verdict::Pass
        );
    }
}
