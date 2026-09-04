use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use trustmesh_credentials::{Credential, VerifiablePresentation, AUTHENTICATION_PURPOSE};
use trustmesh_crypto::{sha256, DidKeyResolver, DidResolver, Signature, SigningKey};

use crate::canonical::canonicalize;
use crate::{Error, DATA_INTEGRITY_PROOF_TYPE, DID_KEY_PREFIX, EDDSA_JCS_2022};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationOutcome {
    pub structural: bool,
    pub proof: bool,
    pub credential_results: Vec<VerificationOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub structural: bool,
    pub proof: bool,
}

pub struct PresentationHolder {
    signing_key: SigningKey,
    verification_method: String,
}

impl PresentationHolder {
    pub fn new(signing_key: SigningKey) -> Self {
        let multikey = signing_key.verifying_key().multikey();
        Self {
            verification_method: format!("{DID_KEY_PREFIX}{multikey}#{multikey}"),
            signing_key,
        }
    }

    /// The did:key identifier that signs presentations.
    pub fn did(&self) -> &str {
        self.verification_method
            .split('#')
            .next()
            .unwrap_or(&self.verification_method)
    }

    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    pub fn sign(
        &self,
        presentation: VerifiablePresentation,
    ) -> Result<VerifiablePresentation, Error> {
        self.sign_at(presentation, Utc::now())
    }

    /// Signs with an explicit `created` instant (deterministic; tests/replay).
    pub fn sign_at(
        &self,
        mut presentation: VerifiablePresentation,
        created: DateTime<Utc>,
    ) -> Result<VerifiablePresentation, Error> {
        presentation
            .validate()
            .map_err(|e| Error::Serialization(e.to_string()))?;
        if presentation.proof.is_some() {
            return Err(Error::AlreadyProven);
        }
        presentation
            .holder
            .get_or_insert_with(|| self.did().to_owned());

        let document =
            serde_json::to_value(&presentation).map_err(|e| Error::Serialization(e.to_string()))?;
        let proof_config = self.proof_config(&document, created)?;
        let hash_data = hash_data(&document, &proof_config)?;
        let signature = self.signing_key.sign(&hash_data);

        let mut proof = trustmesh_credentials::Proof::data_integrity(
            EDDSA_JCS_2022,
            created,
            &self.verification_method,
        );
        proof.proof_purpose = AUTHENTICATION_PURPOSE.to_owned();
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

        presentation.proof = Some(proof);
        Ok(presentation)
    }

    fn proof_config(&self, document: &Value, created: DateTime<Utc>) -> Result<Value, Error> {
        let mut config = json!({
            "type": DATA_INTEGRITY_PROOF_TYPE,
            "cryptosuite": EDDSA_JCS_2022,
            "verificationMethod": self.verification_method,
            "proofPurpose": AUTHENTICATION_PURPOSE,
            "created": trustmesh_credentials::datetime::to_rfc3339(&created),
        });
        if let Some(context) = document.get("@context") {
            config["@context"] = context.clone();
        }
        Ok(config)
    }
}

pub fn verify_presentation(
    presentation: &VerifiablePresentation,
) -> Result<PresentationOutcome, Error> {
    verify_presentation_with(presentation, &DidKeyResolver)
}

pub fn verify_presentation_with(
    presentation: &VerifiablePresentation,
    resolver: &dyn DidResolver,
) -> Result<PresentationOutcome, Error> {
    let structural = presentation.validate().is_ok();

    let proof = presentation.proof.as_ref().ok_or(Error::MissingProof)?;
    if proof.proof_type != DATA_INTEGRITY_PROOF_TYPE {
        return Err(Error::UnsupportedCryptosuite(proof.proof_type.clone()));
    }
    let suite = match &proof.cryptosuite {
        Some(suite) => suite.as_str(),
        None => return Err(Error::UnsupportedCryptosuite("<absent>".into())),
    };
    if suite != EDDSA_JCS_2022 {
        return Err(Error::UnsupportedCryptosuite(suite.to_owned()));
    }
    if proof.proof_purpose != AUTHENTICATION_PURPOSE {
        return Err(Error::Verification);
    }

    let verifying_key = resolver
        .resolve(&proof.verification_method)
        .map_err(|_| Error::InvalidVerificationMethod)?;
    let signature = signature_from_proof_value(presentation)?;

    let document = serde_json::to_value(without_proof(presentation))
        .map_err(|e| Error::Serialization(e.to_string()))?;
    let mut config =
        serde_json::to_value(proof).map_err(|e| Error::Serialization(e.to_string()))?;
    if let Some(object) = config.as_object_mut() {
        object.remove("proofValue");
    }
    if let Some(context) = document.get("@context") {
        config["@context"] = context.clone();
    }

    let document_bytes =
        canonicalize(&document).map_err(|e| Error::Canonicalization(e.to_string()))?;
    let config_bytes = canonicalize(&config).map_err(|e| Error::Canonicalization(e.to_string()))?;
    let mut hash_data = sha256(&config_bytes).to_vec();
    hash_data.extend_from_slice(&sha256(&document_bytes));

    let proof_ok = verifying_key.verify(&hash_data, &signature).is_ok();

    let credential_results = presentation
        .verifiable_credential
        .iter()
        .map(
            |value| match serde_json::from_value::<Credential>(value.clone()) {
                Ok(credential) => {
                    verify_credential_with(&credential, resolver).unwrap_or(VerificationOutcome {
                        structural: false,
                        proof: false,
                    })
                }
                Err(_) => VerificationOutcome {
                    structural: false,
                    proof: false,
                },
            },
        )
        .collect();

    Ok(PresentationOutcome {
        structural,
        proof: proof_ok,
        credential_results,
    })
}

impl PresentationOutcome {
    pub fn valid(&self) -> bool {
        self.structural
            && self.proof
            && self
                .credential_results
                .iter()
                .all(|c| c.structural && c.proof)
    }
}

fn without_proof(presentation: &VerifiablePresentation) -> VerifiablePresentation {
    let mut clone = presentation.clone();
    clone.proof = None;
    clone
}

fn signature_from_proof_value(presentation: &VerifiablePresentation) -> Result<Signature, Error> {
    let proof = presentation.proof.as_ref().ok_or(Error::MissingProof)?;
    let encoded = proof
        .details
        .get("proofValue")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix('z'))
        .ok_or(Error::MalformedProofValue)?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::MalformedProofValue)?;
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| Error::MalformedProofValue)?;
    Ok(Signature::from_bytes(&bytes))
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

// Local alias so presentation.rs doesn't depend on verifier.rs internals.
use crate::verifier;

fn verify_credential_with(
    credential: &Credential,
    resolver: &dyn DidResolver,
) -> Result<VerificationOutcome, Error> {
    let outcome = verifier::verify_credential_with(credential, resolver)?;
    Ok(VerificationOutcome {
        structural: outcome.structural,
        proof: outcome.proof,
    })
}
