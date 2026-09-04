use crate::datetime;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
pub const DATA_INTEGRITY_PROOF_TYPE: &str = "DataIntegrityProof";
pub const EDDSA_RDFC_2022: &str = "eddsa-rdfc-2022";
pub const EDDSA_JCS_2022: &str = "eddsa-jcs-2022";
pub const ASSERTION_METHOD_PURPOSE: &str = "assertionMethod";
pub const AUTHENTICATION_PURPOSE: &str = "authentication";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<crate::Context>>,

    #[serde(rename = "type")]
    pub proof_type: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    pub verification_method: String,

    #[serde(with = "datetime")]
    pub created: DateTime<Utc>,

    #[serde(
        serialize_with = "datetime::serialize_optional",
        deserialize_with = "datetime::deserialize_optional",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expires: Option<DateTime<Utc>>,

    pub proof_purpose: String,

    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub details: Map<String, Value>,
}

impl Proof {
    /// Skeleton for a Data Integrity proof; `proof_value` and friends are
    /// added by the issuer once the signature exists.
    pub fn data_integrity(
        cryptosuite: impl Into<String>,
        created: DateTime<Utc>,
        verification_method: impl Into<String>,
    ) -> Self {
        Self {
            context: None,
            proof_type: DATA_INTEGRITY_PROOF_TYPE.to_owned(),
            cryptosuite: Some(cryptosuite.into()),
            verification_method: verification_method.into(),
            created,
            expires: None,
            proof_purpose: ASSERTION_METHOD_PURPOSE.to_owned(),
            details: Map::new(),
        }
    }
}
