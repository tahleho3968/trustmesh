use std::collections::HashSet;

use trustmesh_credentials::{Status, BITSTRING_STATUS_LIST_ENTRY_TYPE};
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

/// Checks the credential's `credentialStatus` entry against a status list.
///
/// Status lists are fetched (and their proofs checked) by the caller and
/// supplied on [`VerificationContext::with_status_list`]. An entry whose list
/// was not supplied yields [`Verdict::Inconclusive`] — never a silent pass.
/// Only single-bit entries are supported, as permitted by the W3C Bitstring
/// Status List conformance clause; anything else fails explicitly.
pub struct StatusStage;

impl VerificationStage for StatusStage {
    fn name(&self) -> &'static str {
        "status"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        let entry = match ctx.credential().bitstring_status() {
            Ok(None) => return Verdict::Pass,
            Ok(Some(entry)) if entry.status_type == BITSTRING_STATUS_LIST_ENTRY_TYPE => entry,
            Ok(Some(entry)) => {
                return Verdict::Fail(format!(
                    "unsupported credentialStatus type: {}",
                    entry.status_type
                ))
            }
            Err(error) => return Verdict::Fail(format!("malformed credentialStatus: {error}")),
        };

        let supplied = ctx
            .status_lists()
            .iter()
            .find(|list| list.id.as_deref() == Some(entry.status_list_credential.as_str()));
        let Some(list) = supplied else {
            return Verdict::Inconclusive(format!(
                "status list {} was not provided to this verifier",
                entry.status_list_credential
            ));
        };

        match list.expand().and_then(|expanded| expanded.check(&entry)) {
            Ok(Status::Active) => Verdict::Pass,
            Ok(Status::Revoked) => Verdict::Fail("credential has been revoked".into()),
            Ok(Status::Suspended) => Verdict::Fail("credential is currently suspended".into()),
            Err(error) => Verdict::Fail(error.to_string()),
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
    use trustmesh_credentials::{BitstringStatusList, Credential, Subject};
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
    fn status_passes_without_entry_flags_malformed_and_marks_unsupplied_inconclusive() {
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
        assert!(matches!(
            StatusStage.check(&VerificationContext::new(&with_status)),
            Verdict::Inconclusive(reason) if reason.contains("not provided")
        ));
    }

    fn supplied_list(purpose: &str, list_id: &str, set_indexes: &[u64]) -> BitstringStatusList {
        use trustmesh_credentials::compress_bitstring;

        let mut bytes = vec![0u8; 16_384];
        for &index in set_indexes {
            bytes[(index / 8) as usize] |= 0x80u8 >> (index % 8);
        }
        BitstringStatusList {
            id: Some(list_id.to_owned()),
            status_purpose: purpose.to_owned(),
            encoded_list: compress_bitstring(&bytes).expect("list compresses"),
        }
    }

    fn credential_with_entry(entry: trustmesh_credentials::StatusListEntry) -> Credential {
        let issuer = CredentialIssuer::new(trustmesh_crypto::SigningKey::from_bytes(&[7u8; 32]));
        let mut draft = Credential::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer(issuer.did().to_owned())
            .subject(Subject::new().with_id("did:example:graduate-1"))
            .build()
            .unwrap();
        draft.credential_status = Some(serde_json::to_value(&entry).unwrap());
        issuer.issue_at(draft, CREATED()).unwrap()
    }

    #[test]
    fn supplied_list_yields_real_revocation_verdicts() {
        let entry = trustmesh_credentials::StatusListEntry::bitstring(
            "#94567",
            "revocation",
            "94567",
            "https://university.example/status/3",
        );
        let mut credential = credential_with_entry(entry.clone());
        credential.credential_status = Some(serde_json::to_value(entry).expect("entry serializes"));

        // Active: bit unset in the matching list.
        let active_list = supplied_list("revocation", "https://university.example/status/3", &[]);
        assert_eq!(
            StatusStage.check(&VerificationContext::new(&credential).with_status_list(active_list)),
            Verdict::Pass
        );

        // Revoked: bit set.
        let revoked_list = supplied_list(
            "revocation",
            "https://university.example/status/3",
            &[94_567],
        );
        assert_eq!(
            StatusStage
                .check(&VerificationContext::new(&credential).with_status_list(revoked_list)),
            Verdict::Fail("credential has been revoked".into())
        );

        // A different list URL does not satisfy the entry.
        let unrelated_list = supplied_list("revocation", "https://other.example/list", &[94_567]);
        assert!(matches!(
            StatusStage
                .check(&VerificationContext::new(&credential).with_status_list(unrelated_list)),
            Verdict::Inconclusive(_)
        ));
    }

    #[test]
    fn suspension_purpose_fails_when_set() {
        use trustmesh_credentials::StatusListEntry;

        let entry = StatusListEntry::bitstring("#23452", "suspension", "23452", "https://status/4");
        let mut credential = credential_with_entry(entry.clone());
        credential.credential_status = Some(serde_json::to_value(entry).unwrap());

        let suspended_list = supplied_list("suspension", "https://status/4", &[23_452]);
        assert_eq!(
            StatusStage
                .check(&VerificationContext::new(&credential).with_status_list(suspended_list)),
            Verdict::Fail("credential is currently suspended".into())
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
