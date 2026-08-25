//! Staged verification of W3C Verifiable Credentials for TrustMesh.
//!
//! Verification is more than a signature check: a relying party must decide
//! whether a credential is structurally sound, cryptographically proven,
//! unrevoked, and issued by someone it trusts. [`VerificationPipeline`] runs
//! composable [`VerificationStage`]s and returns one serializable
//! [`VerificationResult`] — every stage reports independently, so callers get
//! the full picture instead of the first error.
//!
//! ```
//! use trustmesh_credentials::{Credential, Subject};
//! use trustmesh_crypto::SigningKey;
//! use trustmesh_issuer::CredentialIssuer;
//! use trustmesh_verifier::{TrustPolicyStage, VerificationPipeline};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let issuer = CredentialIssuer::new(SigningKey::generate()?);
//! let draft = Credential::builder()
//!     .context("https://www.w3.org/ns/credentials/examples/v2")
//!     .credential_type("ExampleAlumniCredential")
//!     .issuer(issuer.did().to_owned())
//!     .subject(Subject::new().with_claim("alumniOf", serde_json::json!("Example University")))
//!     .build()?;
//! let signed = issuer.issue(draft)?;
//!
//! // Objective checks plus this verifier's own trust policy.
//! let pipeline = VerificationPipeline::default_pipeline()
//!     .with_stage(Box::new(TrustPolicyStage::allowing([issuer.did()])));
//!
//! let result = pipeline.verify(&signed);
//! assert!(result.valid());
//! assert_eq!(result.stages().len(), 4);
//! # Ok(())
//! # }
//! ```
//!
//! Design decisions are recorded in RFC 0005 (`docs/rfcs/`).

mod pipeline;
mod stages;

pub use pipeline::{
    StageOutcome, Verdict, VerificationContext, VerificationPipeline, VerificationResult,
    VerificationStage,
};
pub use stages::{ProofStage, StatusStage, StructuralStage, TrustPolicyStage};
