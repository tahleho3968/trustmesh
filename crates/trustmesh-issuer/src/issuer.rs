use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use trustmesh_credentials::{Credential, Proof};
use trustmesh_crypto::{sha256, Signature, SigningKey};

use crate::canonical::canonicalize;
use crate::{
    Error, ASSERTION_METHOD_PURPOSE, DATA_INTEGRITY_PROOF_TYPE, DID_KEY_PREFIX, EDDSA_JCS_2022,
};

pub struct CredentialIssuer {
    signing_key: SigningKey,
    verification_method: String,
}

impl CredentialIssuer {
    pub fn new(signing_key: SigningKey) -> Self {
        let multikey = signing_key.verifying_key().multikey();
        Self {
            verification_method: format!("{DID_KEY_PREFIX}{multikey}#{multikey}"),
            signing_key,
        }
    }

    /// The did:key identifier credentials issued by this instance carry.
    pub fn did(&self) -> &str {
        self.verification_method
            .split('#')
            .next()
            .unwrap_or(&self.verification_method)
    }

    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    pub fn issue(&self, draft: Credential) -> Result<Credential, Error> {
        self.issue_at(draft, Utc::now())
    }

    /// Issues with an explicit `created` instant (deterministic; used in tests
    /// and by callers that need reproducible output).
    pub fn issue_at(
        &self,
        mut draft: Credential,
        created: DateTime<Utc>,
    ) -> Result<Credential, Error> {
        draft
            .validate()
            .map_err(|e| Error::Serialization(e.to_string()))?;
        if draft.proof.is_some() {
            return Err(Error::AlreadyProven);
        }
        if draft.issuer.id() != self.did() {
            return Err(Error::IssuerMismatch);
        }

        let document =
            serde_json::to_value(&draft).map_err(|e| Error::Serialization(e.to_string()))?;
        let proof_config = self.proof_config(&document, created)?;
        let hash_data = hash_data(&document, &proof_config)?;
        let signature = self.signing_key.sign(&hash_data);

        let mut proof = Proof::data_integrity(EDDSA_JCS_2022, created, &self.verification_method);
        if let Some(context) = document.get("@context") {
            proof.context = Some(
                serde_json::from_value(context.clone())
                    .map_err(|e| Error::Serialization(e.to_string()))?,
            );
        }
        proof.details.insert(
            "proofValue".into(),
            serde_json::Value::String(multibase_signature(&signature)),
        );

        draft.proof = Some(proof);
        Ok(draft)
    }

    fn proof_config(&self, document: &Value, created: DateTime<Utc>) -> Result<Value, Error> {
        let mut config = json!({
            "type": DATA_INTEGRITY_PROOF_TYPE,
            "cryptosuite": EDDSA_JCS_2022,
            "verificationMethod": self.verification_method,
            "proofPurpose": ASSERTION_METHOD_PURPOSE,
            "created": trustmesh_credentials::datetime::to_rfc3339(&created),
        });
        if let Some(context) = document.get("@context") {
            config["@context"] = context.clone();
        }
        Ok(config)
    }
}

fn multibase_signature(signature: &Signature) -> String {
    format!("z{}", bs58::encode(signature.to_bytes()).into_string())
}

fn hash_data(document: &Value, proof_config: &Value) -> Result<Vec<u8>, Error> {
    let document_bytes =
        canonicalize(document).map_err(|e| Error::Canonicalization(e.to_string()))?;
    let config_bytes =
        canonicalize(proof_config).map_err(|e| Error::Canonicalization(e.to_string()))?;
    let mut hash_data = sha256(&config_bytes).to_vec();
    hash_data.extend_from_slice(&sha256(&document_bytes));
    Ok(hash_data)
}

#[cfg(test)]
mod tests {
    use crate::{
        verify_credential, Error, ASSERTION_METHOD_PURPOSE, DATA_INTEGRITY_PROOF_TYPE,
        DID_KEY_PREFIX, EDDSA_JCS_2022,
    };
    use chrono::TimeZone;
    use trustmesh_credentials::{Credential, Subject};

    const CREATED: fn() -> chrono::DateTime<chrono::Utc> =
        || chrono::Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, 0).unwrap();

    fn issuer_for(seed: [u8; 32]) -> super::CredentialIssuer {
        super::CredentialIssuer::new(trustmesh_crypto::SigningKey::from_bytes(&seed))
    }

    fn draft(issuer: &super::CredentialIssuer) -> Credential {
        Credential::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer(issuer.did().to_owned())
            .subject(
                Subject::new()
                    .with_id("did:example:ebfeb1f712ebc6f1c276e12ec21")
                    .with_claim("alumniOf", serde_json::json!("Example University")),
            )
            .build()
            .expect("valid draft")
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let issuer = issuer_for([9u8; 32]);
        let signed = issuer.issue_at(draft(&issuer), CREATED()).expect("issue");

        signed
            .validate()
            .expect("issued credential stays structurally valid");
        let outcome = verify_credential(&signed).expect("verifiable");
        assert!(outcome.structural);
        assert!(outcome.proof);
    }

    #[test]
    fn proof_shape_matches_spec() {
        let issuer = issuer_for([9u8; 32]);
        let signed = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        let json = serde_json::to_value(&signed).unwrap();
        let proof = &json["proof"];

        assert_eq!(proof["type"], DATA_INTEGRITY_PROOF_TYPE);
        assert_eq!(proof["cryptosuite"], EDDSA_JCS_2022);
        assert_eq!(proof["proofPurpose"], ASSERTION_METHOD_PURPOSE);
        assert_eq!(proof["created"], "2026-08-23T12:00:00Z");
        assert_eq!(proof["@context"], json["@context"]);
        assert_eq!(
            proof["verificationMethod"],
            format!(
                "{}{}#{}",
                DID_KEY_PREFIX,
                issuer.did().trim_start_matches(DID_KEY_PREFIX),
                issuer.did().trim_start_matches(DID_KEY_PREFIX)
            )
        );
        assert!(proof["proofValue"].as_str().unwrap().starts_with('z'));
    }

    #[test]
    fn issuance_is_deterministic_for_fixed_created() {
        let issuer = issuer_for([9u8; 32]);
        let first = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        let second = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        assert_eq!(
            first.proof.as_ref().unwrap(),
            second.proof.as_ref().unwrap()
        );
    }

    #[test]
    fn tampered_claim_rejected() {
        let issuer = issuer_for([9u8; 32]);
        let mut signed = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        signed.credential_subject[0]
            .claims
            .insert("alumniOf".into(), serde_json::json!("Fake University"));
        let outcome = verify_credential(&signed).expect("verification runs");
        assert!(outcome.structural);
        assert!(!outcome.proof);
    }

    #[test]
    fn tampered_proof_value_rejected() {
        let issuer = issuer_for([9u8; 32]);
        let mut signed = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        let proof = signed.proof.as_mut().unwrap();
        let value = proof.details.get_mut("proofValue").unwrap();
        *value = serde_json::Value::String(corrupt_multibase(value.as_str().unwrap()));
        let outcome = verify_credential(&signed).expect("verification runs");
        assert!(!outcome.proof);
    }

    fn corrupt_multibase(value: &str) -> String {
        let mut chars: Vec<char> = value.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == '1' { '2' } else { '1' };
        chars.into_iter().collect()
    }

    #[test]
    fn verification_method_is_bound_to_signature() {
        let signer = issuer_for([9u8; 32]);
        let attacker = issuer_for([8u8; 32]);
        let mut signed = signer.issue_at(draft(&signer), CREATED()).unwrap();
        signed.proof.as_mut().unwrap().details.insert(
            "verificationMethod".into(),
            serde_json::Value::String(attacker.verification_method().to_owned()),
        );
        let outcome = verify_credential(&signed).expect("verification runs");
        assert!(outcome.structural);
        assert!(!outcome.proof);
    }

    #[test]
    fn refuses_to_sign_foreign_issuer() {
        let issuer = issuer_for([9u8; 32]);
        let mut foreign = draft(&issuer);
        foreign.issuer = "https://someone-else.example".into();
        assert_eq!(
            issuer.issue_at(foreign, CREATED()),
            Err(Error::IssuerMismatch)
        );
    }

    #[test]
    fn refuses_to_sign_already_proven() {
        let issuer = issuer_for([9u8; 32]);
        let proven = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        assert_eq!(
            issuer.issue_at(proven, CREATED()),
            Err(Error::AlreadyProven)
        );
    }

    #[test]
    fn unsupported_suite_rejected() {
        let issuer = issuer_for([9u8; 32]);
        let mut signed = issuer.issue_at(draft(&issuer), CREATED()).unwrap();
        signed.proof.as_mut().unwrap().cryptosuite = Some("eddsa-rdfc-2022-not-yet".into());
        assert_eq!(
            verify_credential(&signed),
            Err(Error::UnsupportedCryptosuite(
                "eddsa-rdfc-2022-not-yet".into()
            ))
        );
    }

    #[test]
    fn missing_proof_detected() {
        let issuer = issuer_for([9u8; 32]);
        let unsigned = draft(&issuer);
        assert_eq!(verify_credential(&unsigned), Err(Error::MissingProof));
    }
}
