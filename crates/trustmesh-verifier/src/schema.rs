use jsonschema::Validator;
use serde_json::Value;
use trustmesh_credentials::CredentialSchema;

use crate::pipeline::{Verdict, VerificationContext, VerificationStage};

/// Validates subject claims against a JSON Schema referenced by the credential's
/// `credentialSchema` property.
///
/// The schema itself is not fetched — callers provide the [`Validator`] built
/// from the schema the credential references. This keeps network I/O out of the
/// library and lets the verifier operator decide which schema sources to trust.
///
/// Credentials without a `credentialSchema` pass this stage (schemas are
/// optional in W3C VC 2.0).
pub struct SchemaStage {
    validator: Validator,
    schema_ref: CredentialSchema,
}

impl SchemaStage {
    pub fn try_new(schema_ref: CredentialSchema, schema: &Value) -> Result<Self, String> {
        let validator = Validator::new(schema).map_err(|e| format!("invalid JSON Schema: {e}"))?;
        Ok(Self {
            validator,
            schema_ref,
        })
    }
}

impl VerificationStage for SchemaStage {
    fn name(&self) -> &'static str {
        "schema"
    }

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict {
        let credential = ctx.credential();

        let Some(ref declared) = credential.credential_schema else {
            return Verdict::Pass;
        };

        if declared.id != self.schema_ref.id || declared.schema_type != self.schema_ref.schema_type
        {
            return Verdict::Inconclusive(format!(
                "credential references schema {} ({}) but verifier has {} ({})",
                declared.id, declared.schema_type, self.schema_ref.id, self.schema_ref.schema_type,
            ));
        }

        let subjects = &credential.credential_subject;
        if subjects.is_empty() {
            return Verdict::Fail("no subject claims to validate".into());
        }

        for (i, subject) in subjects.iter().enumerate() {
            let claims = match serde_json::to_value(subject) {
                Ok(v) => v,
                Err(e) => {
                    return Verdict::Fail(format!("subject {i}: failed to serialize claims: {e}"))
                }
            };
            if let Err(error) = self.validator.validate(&claims) {
                return Verdict::Fail(format!(
                    "subject {i} does not conform to schema {}: {error}",
                    self.schema_ref.id,
                ));
            }
        }

        Verdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use trustmesh_credentials::{Credential, CredentialSchema, Subject};
    use trustmesh_crypto::SigningKey;
    use trustmesh_issuer::CredentialIssuer;

    use super::*;
    use crate::pipeline::{VerificationContext, VerificationPipeline};
    use crate::{ProofStage, StructuralStage};

    const SCHEMA_ID: &str = "https://university.example/schemas/alumni-v1";

    fn alumni_schema() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["id", "alumniOf"],
            "properties": {
                "id": { "type": "string" },
                "alumniOf": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    fn signed_credential(
        schema: Option<CredentialSchema>,
        claims: serde_json::Value,
    ) -> Credential {
        let issuer = CredentialIssuer::new(SigningKey::from_bytes(&[5u8; 32]));
        let mut draft = Credential::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer(issuer.did().to_owned())
            .subject(
                Subject::new()
                    .with_id("did:example:graduate-1")
                    .with_claims(claims),
            )
            .build()
            .expect("valid draft");
        draft.credential_schema = schema;
        issuer
            .issue_at(draft, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
            .unwrap()
    }

    fn stage() -> SchemaStage {
        SchemaStage::try_new(
            CredentialSchema {
                id: SCHEMA_ID.to_owned(),
                schema_type: "JsonSchema2020-12".to_owned(),
            },
            &alumni_schema(),
        )
        .expect("valid schema")
    }

    #[test]
    fn passes_without_credential_schema() {
        let credential = signed_credential(None, serde_json::json!({"alumniOf": "Example U"}));
        let ctx = VerificationContext::new(&credential);
        assert_eq!(stage().check(&ctx), Verdict::Pass);
    }

    #[test]
    fn passes_with_conforming_claims() {
        let schema = CredentialSchema {
            id: SCHEMA_ID.to_owned(),
            schema_type: "JsonSchema2020-12".to_owned(),
        };
        let credential = signed_credential(
            Some(schema),
            serde_json::json!({"alumniOf": "Example University"}),
        );
        let ctx = VerificationContext::new(&credential);
        assert_eq!(stage().check(&ctx), Verdict::Pass);
    }

    #[test]
    fn fails_when_required_field_missing() {
        let schema = CredentialSchema {
            id: SCHEMA_ID.to_owned(),
            schema_type: "JsonSchema2020-12".to_owned(),
        };
        let credential =
            signed_credential(Some(schema), serde_json::json!({"id": "did:example:1"}));
        let ctx = VerificationContext::new(&credential);
        assert!(matches!(
            stage().check(&ctx),
            Verdict::Fail(reason) if reason.contains("does not conform")
        ));
    }

    #[test]
    fn fails_on_additional_properties() {
        let schema = CredentialSchema {
            id: SCHEMA_ID.to_owned(),
            schema_type: "JsonSchema2020-12".to_owned(),
        };
        let credential = signed_credential(
            Some(schema),
            serde_json::json!({
                "alumniOf": "Example University",
                "gpa": 3.8
            }),
        );
        let ctx = VerificationContext::new(&credential);
        assert!(matches!(
            stage().check(&ctx),
            Verdict::Fail(reason) if reason.contains("does not conform")
        ));
    }

    #[test]
    fn schema_mismatch_is_inconclusive() {
        let wrong_schema = CredentialSchema {
            id: "https://other.example/schema".to_owned(),
            schema_type: "JsonSchema2020-12".to_owned(),
        };
        let credential = signed_credential(
            Some(wrong_schema),
            serde_json::json!({"alumniOf": "Example University"}),
        );
        let ctx = VerificationContext::new(&credential);
        assert!(matches!(
            stage().check(&ctx),
            Verdict::Inconclusive(reason) if reason.contains("verifier has")
        ));
    }

    #[test]
    fn full_pipeline_with_schema_stage() {
        use crate::TrustPolicyStage;

        let issuer = CredentialIssuer::new(SigningKey::from_bytes(&[5u8; 32]));
        let schema = CredentialSchema {
            id: SCHEMA_ID.to_owned(),
            schema_type: "JsonSchema2020-12".to_owned(),
        };
        let mut draft = Credential::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer(issuer.did().to_owned())
            .subject(
                Subject::new()
                    .with_id("did:example:graduate-1")
                    .with_claims(serde_json::json!({"alumniOf": "Example U"})),
            )
            .build()
            .unwrap();
        draft.credential_schema = Some(schema);
        let signed = issuer
            .issue_at(draft, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
            .unwrap();

        let pipeline = VerificationPipeline::new()
            .with_stage(Box::new(StructuralStage))
            .with_stage(Box::new(ProofStage::default()))
            .with_stage(Box::new(stage()))
            .with_stage(Box::new(TrustPolicyStage::allowing([issuer.did()])));

        let result = pipeline.verify(&signed);
        assert!(result.valid(), "{result:?}");
        assert_eq!(
            result.stage_names(),
            ["structural", "proof", "schema", "trust_policy"]
        );
    }
}
