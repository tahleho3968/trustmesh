//! End-to-end pipeline behavior: independent per-stage reporting,
//! serializable results, and extensibility.

use chrono::TimeZone;
use trustmesh_credentials::{BitstringStatusList, Credential, Subject};
use trustmesh_crypto::{CompositeResolver, DidKeyResolver, SigningKey};
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
        .with_stage(Box::new(ProofStage::default()))
        .verify(&credential);

    assert_eq!(result.stage_names(), ["custom_status", "proof"]);
    assert!(!result.valid());
    assert!(matches!(
        &result.stages()[0].verdict,
        Verdict::Inconclusive(_)
    ));
}

const STATUS_LIST_URL: &str = "https://university.example/status/3";
const ENTRY_INDEX: u64 = 94_567;

/// Issues a credential pointing at a status list, and returns it alongside
/// the list as it would be published (revoked flag controls the entry's bit).
fn credential_and_published_list(revoked: bool) -> (Credential, BitstringStatusList) {
    use trustmesh_credentials::{compress_bitstring, StatusListEntry};

    let issuer = CredentialIssuer::new(SigningKey::from_bytes(&[5u8; 32]));
    let entry = StatusListEntry::bitstring(
        format!("{STATUS_LIST_URL}#{ENTRY_INDEX}"),
        "revocation",
        ENTRY_INDEX.to_string(),
        STATUS_LIST_URL,
    );
    let draft = Credential::builder()
        .context("https://www.w3.org/ns/credentials/examples/v2")
        .credential_type("ExampleAlumniCredential")
        .issuer(issuer.did().to_owned())
        .subject(Subject::new().with_id("did:example:graduate-1"))
        .build()
        .expect("valid draft");
    let mut draft = draft;
    draft.credential_status = Some(serde_json::to_value(&entry).unwrap());
    let signed = issuer.issue_at(draft, CREATED()).expect("issues");

    let mut bits = vec![0u8; 16_384];
    if revoked {
        bits[(ENTRY_INDEX / 8) as usize] |= 0x80u8 >> (ENTRY_INDEX % 8);
    }
    let list = BitstringStatusList {
        id: Some(STATUS_LIST_URL.to_owned()),
        status_purpose: "revocation".to_owned(),
        encoded_list: compress_bitstring(&bits).expect("list compresses"),
    };
    (signed, list)
}

#[test]
fn pipeline_rejects_revoked_credential_when_status_list_supplied() {
    let (credential, list) = credential_and_published_list(true);

    let ctx = VerificationContext::new(&credential).with_status_list(list);
    let result = VerificationPipeline::default_pipeline().verify_with(&ctx);

    assert!(!result.valid());
    let status_failure = result
        .failures()
        .find(|outcome| outcome.stage == "status")
        .expect("status stage must fail");
    assert_eq!(
        status_failure.verdict,
        Verdict::Fail("credential has been revoked".into())
    );
}

#[test]
fn pipeline_accepts_active_credential_whose_status_list_was_supplied() {
    let (credential, list) = credential_and_published_list(false);

    let ctx = VerificationContext::new(&credential).with_status_list(list);
    let result = VerificationPipeline::default_pipeline().verify_with(&ctx);

    assert!(result.valid(), "{result:?}");
}

#[test]
fn unsupplied_status_list_stays_inconclusive_not_invalid() {
    let (credential, _) = credential_and_published_list(true);

    let result = VerificationPipeline::default_pipeline().verify(&credential);

    assert!(matches!(
        &result.stages()[2].verdict,
        Verdict::Inconclusive(reason) if reason.contains(STATUS_LIST_URL)
    ));
}

#[test]
fn proof_stage_accepts_custom_composite_resolver() {
    let (_, credential) = signed_credential();
    let pipeline = VerificationPipeline::new().with_stage(Box::new(ProofStage::with_resolver(
        Box::new(CompositeResolver::new(vec![Box::new(DidKeyResolver)])),
    )));

    let result = pipeline.verify(&credential);
    assert!(result.valid(), "{result:?}");
    assert_eq!(result.stage_names(), ["proof"]);
}
