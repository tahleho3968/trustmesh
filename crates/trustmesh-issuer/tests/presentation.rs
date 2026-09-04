use chrono::TimeZone;
use serde_json::json;
use trustmesh_credentials::{Credential, Subject, VerifiablePresentation};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::{verify_presentation, CredentialIssuer, PresentationHolder};

const CREATED: fn() -> chrono::DateTime<chrono::Utc> =
    || chrono::Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();

fn issuer_for(seed: [u8; 32]) -> CredentialIssuer {
    CredentialIssuer::new(SigningKey::from_bytes(&seed))
}

fn holder_for(seed: [u8; 32]) -> PresentationHolder {
    PresentationHolder::new(SigningKey::from_bytes(&seed))
}

fn signed_credential(seed: [u8; 32]) -> Credential {
    let issuer = issuer_for(seed);
    let draft = Credential::builder()
        .context("https://www.w3.org/ns/credentials/examples/v2")
        .credential_type("ExampleAlumniCredential")
        .issuer(issuer.did().to_owned())
        .subject(
            Subject::new()
                .with_id("did:example:alice")
                .with_claim("alumniOf", json!("Example University")),
        )
        .build()
        .expect("valid draft");
    issuer.issue_at(draft, CREATED()).expect("issue")
}

fn draft_vp(credential: &Credential) -> VerifiablePresentation {
    VerifiablePresentation::builder()
        .context("https://www.w3.org/ns/credentials/examples/v2")
        .presentation_type("CredentialManagerPresentation")
        .credential(serde_json::to_value(credential).unwrap())
        .build()
        .expect("valid presentation draft")
}

#[test]
fn sign_and_verify_single_credential() {
    let holder = holder_for([5u8; 32]);
    let vp = holder
        .sign_at(draft_vp(&signed_credential([9u8; 32])), CREATED())
        .unwrap();
    vp.validate().expect("signed VP stays valid");

    let outcome = verify_presentation(&vp).expect("verify runs");
    assert!(outcome.structural);
    assert!(outcome.proof);
    assert_eq!(outcome.credential_results.len(), 1);
    assert!(outcome.credential_results[0].structural);
    assert!(outcome.credential_results[0].proof);
    assert!(outcome.valid());
}

#[test]
fn sign_and_verify_multiple_credentials() {
    let holder = holder_for([5u8; 32]);
    let mut draft = draft_vp(&signed_credential([9u8; 32]));
    draft
        .verifiable_credential
        .push(serde_json::to_value(signed_credential([8u8; 32])).unwrap());

    let vp = holder.sign_at(draft, CREATED()).unwrap();
    let outcome = verify_presentation(&vp).expect("verify runs");
    assert!(outcome.structural);
    assert!(outcome.proof);
    assert_eq!(outcome.credential_results.len(), 2);
    assert!(outcome.credential_results.iter().all(|c| c.proof));
    assert!(outcome.valid());
}

#[test]
fn holder_is_set_on_sign() {
    let holder = holder_for([5u8; 32]);
    let mut draft = draft_vp(&signed_credential([9u8; 32]));
    draft.holder = None;
    let vp = holder.sign_at(draft, CREATED()).unwrap();
    assert_eq!(vp.holder.as_deref(), Some(holder.did()));
}

#[test]
fn tampered_vp_proof_rejected() {
    let holder = holder_for([5u8; 32]);
    let mut vp = holder
        .sign_at(draft_vp(&signed_credential([9u8; 32])), CREATED())
        .unwrap();
    let proof = vp.proof.as_mut().unwrap();
    let value = proof.details.get_mut("proofValue").unwrap();
    let chars: Vec<char> = value.as_str().unwrap().chars().collect();
    let mid = chars.len() / 2;
    *value = json!(chars
        .into_iter()
        .enumerate()
        .map(|(i, c)| if i == mid {
            if c == '1' {
                '2'
            } else {
                '1'
            }
        } else {
            c
        })
        .collect::<String>());

    let outcome = verify_presentation(&vp).expect("verify runs");
    assert!(outcome.structural);
    assert!(!outcome.proof);
    assert!(!outcome.valid());
}

#[test]
fn tampered_embedded_credential_fails_but_vp_proof_passes() {
    let holder = holder_for([5u8; 32]);
    let mut vp = holder
        .sign_at(draft_vp(&signed_credential([9u8; 32])), CREATED())
        .unwrap();

    let credential: Credential =
        serde_json::from_value(vp.verifiable_credential[0].clone()).unwrap();
    let mut tampered = credential;
    tampered.credential_subject[0]
        .claims
        .insert("alumniOf".into(), json!("Fake University"));
    vp.verifiable_credential[0] = serde_json::to_value(&tampered).unwrap();

    // Re-sign the VP over the tampered credential so the VP proof is valid.
    vp.proof = None;
    let vp = holder.sign_at(vp, CREATED()).unwrap();

    let outcome = verify_presentation(&vp).expect("verify runs");
    assert!(outcome.structural);
    assert!(outcome.proof);
    assert_eq!(outcome.credential_results.len(), 1);
    assert!(outcome.credential_results[0].structural);
    assert!(!outcome.credential_results[0].proof);
    assert!(!outcome.valid());
}

#[test]
fn wrong_holder_key_rejected() {
    let holder = holder_for([5u8; 32]);
    let attacker = holder_for([7u8; 32]);
    let vp = holder
        .sign_at(draft_vp(&signed_credential([9u8; 32])), CREATED())
        .unwrap();
    let mut vp = vp;
    let proof = vp.proof.as_mut().unwrap();
    proof.verification_method = attacker.verification_method().to_owned();
    proof.details.insert(
        "verificationMethod".into(),
        json!(attacker.verification_method()),
    );

    let outcome = verify_presentation(&vp).expect("verify runs");
    assert!(!outcome.proof);
    assert!(!outcome.valid());
}

#[test]
fn proof_purpose_must_be_authentication() {
    let holder = holder_for([5u8; 32]);
    let mut vp = holder
        .sign_at(draft_vp(&signed_credential([9u8; 32])), CREATED())
        .unwrap();
    vp.proof.as_mut().unwrap().proof_purpose = "assertionMethod".to_owned();
    let result = verify_presentation(&vp);
    assert!(result.is_err());
}

#[test]
fn missing_proof_is_error() {
    let vp = draft_vp(&signed_credential([9u8; 32]));
    assert!(verify_presentation(&vp).is_err());
}

#[test]
fn refuses_to_sign_presentation_without_credentials() {
    let holder = holder_for([5u8; 32]);
    let vp = serde_json::from_value::<VerifiablePresentation>(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": []
    }))
    .expect("parse");
    assert!(holder.sign_at(vp, CREATED()).is_err());
}
