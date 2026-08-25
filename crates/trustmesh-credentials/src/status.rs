use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Credential;

pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";
pub const BITSTRING_STATUS_LIST_TYPE: &str = "BitstringStatusList";
pub const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";

/// Minimum uncompressed size mandated by the W3C Bitstring Status List v1.0
/// specification (16 KB = 131,072 single-bit entries), preserving herd privacy.
const MIN_BITSTRING_BYTES: usize = 16_384;

const MULTIBASE_BASE64URL_PREFIX: char = 'u';
const STATUS_SIZE_SINGLE_BIT: u64 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusListEntry {
    pub id: String,

    #[serde(rename = "type")]
    pub status_type: String,

    pub status_purpose: String,

    pub status_list_index: String,

    pub status_list_credential: String,

    /// Present only for multi-bit entries; processors supporting only
    /// single-bit entries MUST error when this differs from 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_size: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<Vec<Value>>,
}

impl StatusListEntry {
    pub fn bitstring(
        id: impl Into<String>,
        purpose: impl Into<String>,
        index: impl Into<String>,
        list_url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status_type: BITSTRING_STATUS_LIST_ENTRY_TYPE.to_owned(),
            status_purpose: purpose.into(),
            status_list_index: index.into(),
            status_list_credential: list_url.into(),
            status_size: None,
            status_message: None,
        }
    }
}

/// Outcome of checking one credential against its status list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Revoked,
    Suspended,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Active => write!(f, "active"),
            Status::Revoked => write!(f, "revoked"),
            Status::Suspended => write!(f, "suspended"),
        }
    }
}

/// Errors raised while consuming or generating status lists. Variants map to
/// the processing errors defined by the W3C Bitstring Status List v1.0
/// specification where applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusError {
    MalformedValue(String),
    UnsupportedStatusSize(u64),
    UnsupportedPurpose(String),
    Decompression(String),
    ListTooShort { got_bytes: usize },
    RangeError { index: u64, entries: u64 },
    PurposeMismatch { entry: String, list: String },
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatusError::MalformedValue(detail) => write!(f, "malformed value: {detail}"),
            StatusError::UnsupportedStatusSize(size) => write!(
                f,
                "unsupported statusSize {size}: only single-bit entries are supported"
            ),
            StatusError::UnsupportedPurpose(purpose) => {
                write!(f, "unsupported statusPurpose: {purpose}")
            }
            StatusError::Decompression(detail) => {
                write!(f, "encodedList is not valid GZIP data: {detail}")
            }
            StatusError::ListTooShort { got_bytes } => write!(
                f,
                "STATUS_LIST_LENGTH_ERROR: uncompressed bitstring is {got_bytes} bytes, \
                 below the 16384-byte minimum required for herd privacy"
            ),
            StatusError::RangeError { index, entries } => write!(
                f,
                "RANGE_ERROR: statusListIndex {index} is outside the list ({entries} entries)"
            ),
            StatusError::PurposeMismatch { entry, list } => write!(
                f,
                "STATUS_VERIFICATION_ERROR: entry purpose {entry:?} does not match list purpose {list:?}"
            ),
        }
    }
}

impl std::error::Error for StatusError {}

/// The `BitstringStatusList` subject of a fetched, proof-checked
/// `BitstringStatusListCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusList {
    /// `id` of the enclosing status list credential; the value
    /// `BitstringStatusListEntry::status_list_credential` URLs point at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub status_purpose: String,

    pub encoded_list: String,
}

impl BitstringStatusList {
    /// Extracts the status list from its enclosing credential. Callers must
    /// have verified the credential's proofs first; this type performs no
    /// cryptographic checks itself.
    pub fn from_credential(list_credential: &Credential) -> Result<Self, StatusError> {
        let expected_type = BITSTRING_STATUS_LIST_CREDENTIAL_TYPE;
        if !list_credential.types.iter().any(|t| t == expected_type) {
            return Err(StatusError::MalformedValue(format!(
                "status list credential type must include {expected_type}"
            )));
        }
        let subject = list_credential.credential_subject.first().ok_or_else(|| {
            StatusError::MalformedValue("status list credential has no subject".into())
        })?;
        let claims = Value::Object(subject.claims.clone());
        Self::from_parts(list_credential.id.clone(), &claims)
    }

    /// Parses the raw JSON form of the subject (`type`, `statusPurpose`,
    /// `encodedList`).
    pub fn from_parts(id: Option<String>, subject: &Value) -> Result<Self, StatusError> {
        let malformed = |detail: &str| StatusError::MalformedValue(detail.to_owned());
        if subject.get("type").and_then(Value::as_str) != Some(BITSTRING_STATUS_LIST_TYPE) {
            return Err(malformed(
                "credentialSubject.type must be \"BitstringStatusList\"",
            ));
        }
        let purpose = subject
            .get("statusPurpose")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| malformed("credentialSubject.statusPurpose must be a string"))?;
        let encoded_list = subject
            .get("encodedList")
            .and_then(Value::as_str)
            .filter(|e| !e.is_empty())
            .ok_or_else(|| malformed("credentialSubject.encodedList must be a string"))?;
        if let Some(size) = subject.get("statusSize") {
            let size = size.as_u64().ok_or_else(|| {
                malformed("credentialSubject.statusSize must be a positive integer")
            })?;
            ensure_single_bit(size)?;
        }
        Ok(Self {
            id,
            status_purpose: purpose.to_owned(),
            encoded_list: encoded_list.to_owned(),
        })
    }

    /// Decodes `encodedList` per the Bitstring Expansion Algorithm:
    /// multibase base64url-no-pad decode, then GZIP decompression, then
    /// minimum-length validation.
    pub fn expand(&self) -> Result<ExpandedStatusList, StatusError> {
        let compressed = decode_multibase_base64url(&self.encoded_list)?;
        let bytes = gunzip(&compressed)?;
        if bytes.len() < MIN_BITSTRING_BYTES {
            return Err(StatusError::ListTooShort {
                got_bytes: bytes.len(),
            });
        }
        Ok(ExpandedStatusList {
            id: self.id.clone(),
            purpose: self.status_purpose.clone(),
            bytes,
        })
    }
}

/// A decoded status bitstring ready for entry lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedStatusList {
    pub id: Option<String>,
    pub purpose: String,
    bytes: Vec<u8>,
}

impl ExpandedStatusList {
    /// Number of single-bit status positions in the list.
    pub fn entry_count(&self) -> u64 {
        self.bytes.len() as u64 * 8
    }

    /// Raw bit value at `index`; indexes count from zero with each byte read
    /// most-significant bit first.
    pub fn is_set(&self, index: u64) -> Result<bool, StatusError> {
        let entries = self.entry_count();
        if index >= entries {
            return Err(StatusError::RangeError { index, entries });
        }
        let mask = 0x80u8 >> (index % 8);
        Ok(self.bytes[(index / 8) as usize] & mask != 0)
    }

    /// Applies the specification's validate algorithm to one status entry:
    /// purpose match, index range, then bit semantics per purpose.
    pub fn check(&self, entry: &StatusListEntry) -> Result<Status, StatusError> {
        if entry.status_type != BITSTRING_STATUS_LIST_ENTRY_TYPE {
            return Err(StatusError::MalformedValue(format!(
                "credentialStatus.type must be {BITSTRING_STATUS_LIST_ENTRY_TYPE}"
            )));
        }
        if entry.status_purpose != self.purpose {
            return Err(StatusError::PurposeMismatch {
                entry: entry.status_purpose.clone(),
                list: self.purpose.clone(),
            });
        }
        if let Some(size) = entry.status_size {
            ensure_single_bit(size)?;
        }
        let index: u64 = entry.status_list_index.parse().map_err(|_| {
            StatusError::MalformedValue("statusListIndex must be a base-10 integer".to_owned())
        })?;
        match (self.is_set(index)?, self.purpose.as_str()) {
            (false, _) => Ok(Status::Active),
            (true, "revocation") => Ok(Status::Revoked),
            (true, "suspension") => Ok(Status::Suspended),
            (true, other) => Err(StatusError::UnsupportedPurpose(other.to_owned())),
        }
    }
}

/// Encodes a bitstring for publication in a `BitstringStatusList`:
/// GZIP compression followed by multibase base64url-no-padding.
pub fn compress_bitstring(bytes: &[u8]) -> Result<String, StatusError> {
    if bytes.len() < MIN_BITSTRING_BYTES {
        return Err(StatusError::ListTooShort {
            got_bytes: bytes.len(),
        });
    }
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(bytes)
        .and_then(|_| encoder.finish())
        .map_err(|e| StatusError::Decompression(e.to_string()))
        .map(|compressed| {
            format!(
                "{MULTIBASE_BASE64URL_PREFIX}{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(compressed)
            )
        })
}

fn ensure_single_bit(size: u64) -> Result<(), StatusError> {
    if size == STATUS_SIZE_SINGLE_BIT {
        Ok(())
    } else {
        Err(StatusError::UnsupportedStatusSize(size))
    }
}

fn decode_multibase_base64url(encoded: &str) -> Result<Vec<u8>, StatusError> {
    let body = encoded
        .strip_prefix(MULTIBASE_BASE64URL_PREFIX)
        .ok_or_else(|| {
            StatusError::MalformedValue(
                "encodedList must be multibase base64url-no-pad (\"u\" prefix)".to_owned(),
            )
        })?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| StatusError::MalformedValue(format!("invalid base64url: {e}")))
}

fn gunzip(compressed: &[u8]) -> Result<Vec<u8>, StatusError> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(compressed);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .map_err(|e| StatusError::Decompression(e.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VERIFIABLE_CREDENTIAL_TYPE;

    const SPEC_EXAMPLE_ENCODED_LIST: &str =
        "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";

    fn empty_list_bytes() -> Vec<u8> {
        vec![0u8; MIN_BITSTRING_BYTES]
    }

    fn list_with_set_bits(indexes: &[u64], total_entries: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; total_entries.div_ceil(8)];
        for &index in indexes {
            bytes[(index / 8) as usize] |= 0x80u8 >> (index % 8);
        }
        bytes
    }

    fn expanded(purpose: &str, bytes: Vec<u8>) -> ExpandedStatusList {
        ExpandedStatusList {
            id: None,
            purpose: purpose.to_owned(),
            bytes,
        }
    }

    fn revocation_entry(index: &str) -> StatusListEntry {
        StatusListEntry::bitstring(
            "https://university.example/status/3#94567",
            "revocation",
            index,
            "https://university.example/status/3",
        )
    }

    #[test]
    fn w3c_spec_example_expands_to_minimum_size_empty_list() {
        let list = BitstringStatusList {
            id: Some("https://example.com/credentials/status/3".into()),
            status_purpose: "revocation".into(),
            encoded_list: SPEC_EXAMPLE_ENCODED_LIST.into(),
        };
        let expanded = list.expand().expect("spec example must expand");
        assert_eq!(expanded.bytes.len(), MIN_BITSTRING_BYTES);
        assert_eq!(expanded.entry_count(), 131_072);
        assert_eq!(
            expanded.check(&revocation_entry("94567")),
            Ok(Status::Active)
        );
    }

    #[test]
    fn bit_order_is_msb_first_within_each_byte() {
        // Byte 0: 0x80 sets index 0 only; 0x01 sets index 7 only.
        let mut bytes = empty_list_bytes();
        bytes[0] = 0x80;
        let msb_set = expanded("revocation", bytes);
        assert_eq!(msb_set.check(&revocation_entry("0")), Ok(Status::Revoked));
        assert_eq!(msb_set.check(&revocation_entry("7")), Ok(Status::Active));

        let mut bytes = empty_list_bytes();
        bytes[0] = 0x01;
        let lsb_set = expanded("revocation", bytes);
        assert_eq!(lsb_set.check(&revocation_entry("0")), Ok(Status::Active));
        assert_eq!(lsb_set.check(&revocation_entry("7")), Ok(Status::Revoked));

        // Last byte, last bit.
        let mut bytes = empty_list_bytes();
        let last = bytes.len() - 1;
        bytes[last] = 0x01;
        let tail_set = expanded("revocation", bytes);
        assert_eq!(
            tail_set.check(&revocation_entry("131071")),
            Ok(Status::Revoked)
        );
    }

    #[test]
    fn suspension_purpose_reports_suspended_when_set() {
        let expanded = expanded(
            "suspension",
            list_with_set_bits(&[42], MIN_BITSTRING_BYTES * 8),
        );
        let entry = StatusListEntry::bitstring("#42", "suspension", "42", "https://list");
        assert_eq!(expanded.check(&entry), Ok(Status::Suspended));
    }

    #[test]
    fn purpose_mismatch_is_an_error() {
        let expanded = expanded("revocation", empty_list_bytes());
        let entry = StatusListEntry::bitstring("#1", "suspension", "1", "https://list");
        assert_eq!(
            expanded.check(&entry),
            Err(StatusError::PurposeMismatch {
                entry: "suspension".into(),
                list: "revocation".into(),
            })
        );
    }

    #[test]
    fn out_of_range_index_is_a_range_error() {
        let expanded = expanded("revocation", empty_list_bytes());
        assert_eq!(
            expanded.check(&revocation_entry("131072")),
            Err(StatusError::RangeError {
                index: 131_072,
                entries: 131_072,
            })
        );
    }

    #[test]
    fn undersized_lists_are_rejected() {
        // Hand-compress an illegally small bitstring; compress_bitstring
        // refuses to produce one itself.
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0u8; 100]).expect("writes");
        let encoded = format!(
            "u{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(encoder.finish().expect("finishes"))
        );

        let list = BitstringStatusList {
            id: None,
            status_purpose: "revocation".into(),
            encoded_list: encoded,
        };
        assert_eq!(
            list.expand(),
            Err(StatusError::ListTooShort { got_bytes: 100 })
        );
    }

    #[test]
    fn multi_bit_lists_are_rejected_with_clear_error() {
        let claims = serde_json::json!({
            "type": "BitstringStatusList",
            "statusPurpose": "message",
            "encodedList": SPEC_EXAMPLE_ENCODED_LIST,
            "statusSize": 2
        });
        assert_eq!(
            BitstringStatusList::from_parts(None, &claims),
            Err(StatusError::UnsupportedStatusSize(2))
        );

        let mut entry = revocation_entry("1");
        entry.status_size = Some(2);
        let expanded = expanded("revocation", empty_list_bytes());
        assert_eq!(
            expanded.check(&entry),
            Err(StatusError::UnsupportedStatusSize(2))
        );
    }

    #[test]
    fn malformed_encoded_lists_are_rejected() {
        for (detail, encoded) in [
            ("missing multibase prefix", "H4sIAAAAAAAAAAAAAA"),
            ("invalid base64url body", "u!!!!"),
            ("valid base64url, not gzip", "uAAAA"),
        ] {
            let list = BitstringStatusList {
                id: None,
                status_purpose: "revocation".into(),
                encoded_list: encoded.into(),
            };
            let error = list.expand().unwrap_err();
            assert!(
                matches!(
                    error,
                    StatusError::MalformedValue(_) | StatusError::Decompression(_)
                ),
                "{detail}: {error}"
            );
        }
    }

    #[test]
    fn compress_roundtrips_through_expand_and_check() {
        let indexes = [0, 12_345, 65_536, 131_071];
        let encoded =
            compress_bitstring(&list_with_set_bits(&indexes, 131_072)).expect("compresses");
        let list = BitstringStatusList {
            id: None,
            status_purpose: "revocation".into(),
            encoded_list: encoded,
        };
        let expanded = list.expand().expect("expands");

        for index in 0..131_072u64 {
            let expected = if indexes.contains(&index) {
                Status::Revoked
            } else {
                Status::Active
            };
            assert_eq!(
                expanded.check(&revocation_entry(&index.to_string())),
                Ok(expected),
                "index {index}"
            );
        }
    }

    #[test]
    fn from_credential_extracts_subject_and_matches_by_id() {
        let credential: Credential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "https://example.com/credentials/status/3",
            "type": [VERIFIABLE_CREDENTIAL_TYPE, BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
            "issuer": "did:key:z6Mk",
            "validFrom": "2021-04-05T14:27:40Z",
            "credentialSubject": {
                "id": "https://example.com/status/3#list",
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": SPEC_EXAMPLE_ENCODED_LIST
            }
        }))
        .expect("valid status list credential");

        let list = BitstringStatusList::from_credential(&credential).expect("extracts");
        assert_eq!(
            list.id.as_deref(),
            Some("https://example.com/credentials/status/3")
        );
        assert_eq!(list.status_purpose, "revocation");
        assert!(list.expand().is_ok());

        let wrong_type: Credential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": [VERIFIABLE_CREDENTIAL_TYPE],
            "issuer": "did:key:z6Mk",
            "validFrom": "2021-04-05T14:27:40Z",
            "credentialSubject": {"type": "Person"}
        }))
        .expect("valid plain credential");
        assert_eq!(
            BitstringStatusList::from_credential(&wrong_type),
            Err(StatusError::MalformedValue(
                "status list credential type must include BitstringStatusListCredential".into()
            ))
        );
    }

    #[test]
    fn subject_without_required_fields_is_malformed() {
        let missing_purpose = serde_json::json!({"type": "BitstringStatusList"});
        assert!(matches!(
            BitstringStatusList::from_parts(None, &missing_purpose),
            Err(StatusError::MalformedValue(_))
        ));
        let wrong_type = serde_json::json!({
            "type": "SomethingElse",
            "statusPurpose": "revocation",
            "encodedList": SPEC_EXAMPLE_ENCODED_LIST
        });
        assert!(matches!(
            BitstringStatusList::from_parts(None, &wrong_type),
            Err(StatusError::MalformedValue(_))
        ));
    }

    #[test]
    fn non_numeric_index_is_malformed() {
        let expanded = expanded("revocation", empty_list_bytes());
        let entry = revocation_entry("not-a-number");
        assert!(matches!(
            expanded.check(&entry),
            Err(StatusError::MalformedValue(_))
        ));
    }

    #[test]
    fn message_purpose_bit_set_reports_unsupported() {
        let expanded = expanded("message", list_with_set_bits(&[5], MIN_BITSTRING_BYTES * 8));
        let entry = StatusListEntry::bitstring("#5", "message", "5", "https://list");
        assert_eq!(
            expanded.check(&entry),
            Err(StatusError::UnsupportedPurpose("message".into()))
        );
    }

    #[test]
    fn entry_serialization_skips_optional_fields() {
        let json = serde_json::to_value(revocation_entry("94567")).unwrap();
        assert!(json.get("statusSize").is_none());
        assert!(json.get("statusMessage").is_none());
        let parsed: StatusListEntry = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.status_size, None);

        let sized = serde_json::from_value::<StatusListEntry>(serde_json::json!({
            "id": "#1", "type": "BitstringStatusListEntry", "statusPurpose": "message",
            "statusListIndex": "1", "statusListCredential": "https://list",
            "statusSize": 2
        }))
        .unwrap();
        assert_eq!(sized.status_size, Some(2));
    }
}
