//! End-to-end pipeline behavior: independent per-stage reporting,
//! serializable results, and extensibility.

use chrono::TimeZone;
use trustmesh_credentials::{Credential, Subject};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::CredentialIssuer;
use trustmesh_verifier::{
    ProofStage, TrustPolicyStage, Verdict, VerificationContext, VerificationPipeline,
    VerificationResult, VerificationStage,
};

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
fn default_pipeline_accepts_genuine_credential() {
    let (_, credential) = signed_credential();
    let result = VerificationPipeline::default_pipeline().verify(&credential);

    assert!(result.valid(), "{result:?}");
    assert_eq!(result.stage_names(), ["structural", "proof", "status"]);
}

#[test]
fn stages_report_failures_independently() {
    let (_, mut credential) = signed_credential();
    credential.credential_subject[0]
        .claims
        .insert("alumniOf".into(), serde_json::json!("Fake University"));
    credential.issuer = "https://someone-else.example".into();

    let pipeline = VerificationPipeline::default_pipeline().with_stage(Box::new(
        TrustPolicyStage::allowing(["did:key:z6MkTrusted"]),
    ));
    let result = pipeline.verify(&credential);

    assert!(!result.valid());
    let failed: Vec<&str> = result
        .failures()
        .map(|outcome| outcome.stage.as_str())
        .collect();
    assert_eq!(failed, ["proof", "trust_policy"], "{result:?}");
}

#[test]
fn trust_policy_is_opt_in_and_denies_unlisted_issuers() {
    let (issuer, credential) = signed_credential();

    let without_policy = VerificationPipeline::default_pipeline().verify(&credential);
    assert!(without_policy.valid());

    let with_other_policy = VerificationPipeline::default_pipeline()
        .with_stage(Box::new(TrustPolicyStage::allowing(["did:key:z6MkOther"])));
    let result = with_other_policy.verify(&credential);
    assert!(!result.valid());
    assert!(matches!(
        &result.stages()[3].verdict,
        Verdict::Fail(reason) if reason.contains(issuer.did())
    ));

    let with_matching_policy = VerificationPipeline::default_pipeline()
        .with_stage(Box::new(TrustPolicyStage::allowing([issuer.did()])));
    assert!(with_matching_policy.verify(&credential).valid());
}

#[test]
fn results_serialize_for_logging_and_roundtrip() {
    let (_, credential) = signed_credential();
    let result = VerificationPipeline::default_pipeline()
        .with_stage(Box::new(TrustPolicyStage::allowing(["did:key:z6MkOther"])))
        .verify(&credential);

    let json = serde_json::to_string_pretty(&result).expect("serializable");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["stages"][0]["stage"], "structural");
    assert_eq!(value["stages"][0]["verdict"], serde_json::json!("pass"));
    assert!(value["stages"][3]["verdict"].get("fail").is_some());

    let parsed: VerificationResult = serde_json::from_str(&json).expect("deserializable");
    assert_eq!(parsed, result);
    assert_eq!(parsed.valid(), result.valid());
}

struct FlakyStatusStage;

impl VerificationStage for FlakyStatusStage {
    fn name(&self) -> &'static str {
        "custom_status"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        if ctx.credential().credential_status.is_some() {
            Verdict::Pass
        } else {
            Verdict::Inconclusive("no status entry to inspect".into())
        }
    }
}

#[test]
fn custom_stages_compose_with_builtin_ones() {
    let (_, credential) = signed_credential();
    let result = VerificationPipeline::new()
        .with_stage(Box::new(FlakyStatusStage))
        .with_stage(Box::new(ProofStage))
        .verify(&credential);

    assert_eq!(result.stage_names(), ["custom_status", "proof"]);
    assert!(!result.valid());
    assert!(matches!(
        &result.stages()[0].verdict,
        Verdict::Inconclusive(_)
    ));
}
