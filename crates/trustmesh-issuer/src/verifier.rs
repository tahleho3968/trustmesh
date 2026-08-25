use serde_json::Value;
use trustmesh_credentials::Credential;
use trustmesh_crypto::{sha256, DidKeyResolver, DidResolver, Signature};

use crate::canonical::canonicalize;
use crate::{Error, ASSERTION_METHOD_PURPOSE, DATA_INTEGRITY_PROOF_TYPE, EDDSA_JCS_2022};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub structural: bool,
    pub proof: bool,
}

pub fn verify_credential(credential: &Credential) -> Result<VerificationOutcome, Error> {
    verify_credential_with(credential, &DidKeyResolver)
}

pub fn verify_credential_with(
    credential: &Credential,
    resolver: &dyn DidResolver,
) -> Result<VerificationOutcome, Error> {
    let structural = credential.validate().is_ok();

    let proof = credential.proof.as_ref().ok_or(Error::MissingProof)?;
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
    if proof.proof_purpose != ASSERTION_METHOD_PURPOSE {
        return Err(Error::Verification);
    }

    let verifying_key = resolver
        .resolve(&proof.verification_method)
        .map_err(|_| Error::InvalidVerificationMethod)?;
    let signature = signature_from_proof_value(credential)?;

    let document = serde_json::to_value(without_proof(credential))
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
    Ok(VerificationOutcome {
        structural,
        proof: proof_ok,
    })
}

fn without_proof(credential: &Credential) -> Credential {
    let mut clone = credential.clone();
    clone.proof = None;
    clone
}

fn signature_from_proof_value(credential: &Credential) -> Result<Signature, Error> {
    let proof = credential.proof.as_ref().ok_or(Error::MissingProof)?;
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
