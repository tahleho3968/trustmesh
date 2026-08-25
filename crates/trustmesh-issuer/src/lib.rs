pub mod canonical;

mod error;
mod issuer;
mod verifier;

pub use error::Error;
pub use issuer::CredentialIssuer;
pub use verifier::{verify_credential, verify_credential_with, VerificationOutcome};

pub const DATA_INTEGRITY_PROOF_TYPE: &str = "DataIntegrityProof";
pub const EDDSA_JCS_2022: &str = "eddsa-jcs-2022";
pub const ASSERTION_METHOD_PURPOSE: &str = "assertionMethod";
pub const DID_KEY_PREFIX: &str = "did:key:";
