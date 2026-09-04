pub mod datetime;

mod credential;
mod error;
mod issuer;
mod presentation;
mod proof;
mod status;
mod subject;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use credential::{Credential, CredentialSchema};
pub use error::Error;
pub use issuer::Issuer;
pub use presentation::{PresentationBuilder, VerifiablePresentation};
pub use proof::{
    Proof, ASSERTION_METHOD_PURPOSE, AUTHENTICATION_PURPOSE, DATA_INTEGRITY_PROOF_TYPE,
    EDDSA_JCS_2022, EDDSA_RDFC_2022,
};
pub use status::{
    compress_bitstring, BitstringStatusList, ExpandedStatusList, Status, StatusError,
    StatusListEntry, BITSTRING_STATUS_LIST_CREDENTIAL_TYPE, BITSTRING_STATUS_LIST_ENTRY_TYPE,
    BITSTRING_STATUS_LIST_TYPE,
};
pub use subject::Subject;

pub const BASE_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const VERIFIABLE_CREDENTIAL_TYPE: &str = "VerifiableCredential";
pub const VERIFIABLE_PRESENTATION_TYPE: &str = "VerifiablePresentation";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Context {
    Url(String),
    Object(Map<String, Value>),
}

impl From<&str> for Context {
    fn from(value: &str) -> Self {
        Context::Url(value.to_owned())
    }
}

impl From<String> for Context {
    fn from(value: String) -> Self {
        Context::Url(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_accepts_string_and_object_forms() {
        let json = r#"["https://example.org/vocab", {"vocab": "https://example.org/#"}]"#;
        let parsed: Vec<Context> = serde_json::from_str(json).expect("valid contexts");
        assert_eq!(
            parsed[0],
            Context::Url("https://example.org/vocab".to_owned())
        );
        assert!(matches!(parsed[1], Context::Object(_)));
    }
}
