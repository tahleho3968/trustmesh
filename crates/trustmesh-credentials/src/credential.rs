use super::{Error, BASE_CONTEXT, VERIFIABLE_CREDENTIAL_TYPE};
use crate::issuer::Issuer;
use crate::proof::Proof;
use crate::status::StatusListEntry;
use crate::subject::Subject;
use crate::{datetime, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Vec<Context>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub types: Vec<String>,

    pub issuer: Issuer,

    #[serde(
        serialize_with = "datetime::serialize_optional",
        deserialize_with = "datetime::deserialize_optional",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_from: Option<DateTime<Utc>>,

    #[serde(
        serialize_with = "datetime::serialize_optional",
        deserialize_with = "datetime::deserialize_optional",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_until: Option<DateTime<Utc>>,

    #[serde(
        serialize_with = "serialize_subjects",
        deserialize_with = "deserialize_subjects"
    )]
    pub credential_subject: Vec<Subject>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,

    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extensions: Map<String, Value>,
}

impl Credential {
    pub fn builder() -> CredentialBuilder {
        CredentialBuilder::default()
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self.context.first() {
            Some(Context::Url(url)) if url == BASE_CONTEXT => {}
            _ => return Err(Error::MissingBaseContext),
        }

        if !self.types.iter().any(|t| t == VERIFIABLE_CREDENTIAL_TYPE) {
            return Err(Error::MissingBaseType);
        }

        if self.credential_subject.is_empty() {
            return Err(Error::NoSubjects);
        }

        if let (Some(from), Some(until)) = (self.valid_from, self.valid_until) {
            if from > until {
                return Err(Error::InvalidValidityPeriod);
            }
        }

        Ok(())
    }

    /// Parses `credential_status` as a Bitstring Status List entry.
    pub fn bitstring_status(&self) -> Result<Option<StatusListEntry>, serde_json::Error> {
        match &self.credential_status {
            None => Ok(None),
            Some(value) => serde_json::from_value(value.clone()).map(Some),
        }
    }
}

fn serialize_subjects<S>(subjects: &[Subject], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match subjects {
        [single] => serde_json::to_value(single)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer),
        many => many.serialize(serializer),
    }
}

fn deserialize_subjects<'de, D>(deserializer: D) -> Result<Vec<Subject>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Object(_) => Ok(vec![
            Subject::deserialize(value).map_err(serde::de::Error::custom)?
        ]),
        Value::Array(items) => items
            .into_iter()
            .map(|item| Subject::deserialize(item).map_err(serde::de::Error::custom))
            .collect(),
        _ => Err(serde::de::Error::custom(
            "credentialSubject must be an object or an array of objects",
        )),
    }
}

#[derive(Debug, Default)]
pub struct CredentialBuilder {
    context: Vec<Context>,
    id: Option<String>,
    types: Vec<String>,
    issuer: Option<Issuer>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    subjects: Vec<Subject>,
}

impl CredentialBuilder {
    pub fn context(mut self, context: impl Into<Context>) -> Self {
        self.context.push(context.into());
        self
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn credential_type(mut self, type_: impl Into<String>) -> Self {
        let type_ = type_.into();
        if !self.types.contains(&type_) {
            self.types.push(type_);
        }
        self
    }

    pub fn issuer(mut self, issuer: impl Into<Issuer>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn valid_from(mut self, at: DateTime<Utc>) -> Self {
        self.valid_from = Some(at);
        self
    }

    pub fn valid_until(mut self, at: DateTime<Utc>) -> Self {
        self.valid_until = Some(at);
        self
    }

    pub fn subject(mut self, subject: Subject) -> Self {
        self.subjects.push(subject);
        self
    }

    pub fn build(self) -> Result<Credential, Error> {
        let mut context = self.context;
        if !matches!(context.first(), Some(Context::Url(url)) if url == BASE_CONTEXT) {
            context.insert(0, BASE_CONTEXT.into());
        }

        let mut types = self.types;
        if !types.iter().any(|t| t == VERIFIABLE_CREDENTIAL_TYPE) {
            types.insert(0, VERIFIABLE_CREDENTIAL_TYPE.to_owned());
        }

        let credential = Credential {
            context,
            id: self.id,
            types,
            issuer: self.issuer.ok_or(Error::MissingIssuer)?,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            credential_subject: self.subjects,
            credential_status: None,
            proof: None,
            extensions: Map::new(),
        };
        credential.validate()?;
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use crate::status::StatusListEntry;
    use crate::{BASE_CONTEXT, VERIFIABLE_CREDENTIAL_TYPE};
    use chrono::TimeZone;

    use super::*;

    fn example_credential() -> Result<Credential, Error> {
        Credential::builder()
            .id("http://university.example/credentials/3732")
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .credential_type("ExampleAlumniCredential")
            .issuer("https://university.example/issuers/565049")
            .subject(Subject::new().with_id("did:example:ebfeb1f712ebc6f1c276e12ec21"))
            .build()
    }

    #[test]
    fn builder_applies_required_defaults() {
        let credential = example_credential().expect("valid credential");
        assert_eq!(credential.context[0], BASE_CONTEXT.into());
        assert_eq!(credential.types[0], VERIFIABLE_CREDENTIAL_TYPE);
        assert!(credential.validate().is_ok());
        assert!(credential.proof.is_none());
    }

    #[test]
    fn serializes_with_spec_field_names() {
        let json = serde_json::to_value(example_credential().unwrap()).unwrap();
        assert_eq!(json["@context"][0], BASE_CONTEXT);
        assert_eq!(json["type"][1], "ExampleAlumniCredential");
        assert_eq!(json["issuer"], "https://university.example/issuers/565049");
        assert_eq!(
            json["credentialSubject"]["id"],
            "did:example:ebfeb1f712ebc6f1c276e12ec21"
        );
        assert!(json.get("validFrom").is_none());
        assert!(json.get("extensions").is_none());
    }

    #[test]
    fn spec_example_roundtrips() {
        let raw = r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleAlumniCredential"],
            "issuer": "https://university.example/issuers/565049",
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "alumniOf": {"id": "did:example:c276e12ec21ebfeb1f712ebc6f1"}
            },
            "termsOfUse": [{"type": "IssuerPolicy"}]
        }"#;
        let original: Value = serde_json::from_str(raw).unwrap();
        let credential: Credential = serde_json::from_value(original.clone()).unwrap();
        credential.validate().expect("spec example must validate");

        assert_eq!(
            credential.valid_from,
            Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
        );
        assert_eq!(
            credential.extensions["termsOfUse"][0]["type"],
            "IssuerPolicy"
        );

        let reserialized = serde_json::to_value(&credential).unwrap();
        assert_eq!(reserialized, original);
    }

    #[test]
    fn datetimes_serialize_with_z_suffix_and_parse_offsets() {
        let from = Utc.with_ymd_and_hms(2026, 8, 23, 10, 30, 0).unwrap();
        let until = Utc.with_ymd_and_hms(2031, 8, 23, 10, 30, 0).unwrap();
        let mut credential = example_credential().unwrap();
        credential.valid_from = Some(from);
        credential.valid_until = Some(until);

        let json = serde_json::to_string(&credential).unwrap();
        assert!(json.contains("\"validFrom\":\"2026-08-23T10:30:00Z\""));
        assert!(json.contains("\"validUntil\":\"2031-08-23T10:30:00Z\""));

        let parsed = DateTime::parse_from_rfc3339("2031-08-23T12:30:00+02:00")
            .expect("valid RFC 3339 with offset")
            .with_timezone(&Utc);
        assert_eq!(parsed, until);
    }

    #[test]
    fn rejects_missing_base_context_or_type_or_subjects() {
        let mut credential = example_credential().unwrap();
        credential.context.clear();
        assert_eq!(credential.validate(), Err(Error::MissingBaseContext));

        credential.context.push(BASE_CONTEXT.into());
        credential.types.retain(|t| t != VERIFIABLE_CREDENTIAL_TYPE);
        assert_eq!(credential.validate(), Err(Error::MissingBaseType));

        credential
            .types
            .insert(0, VERIFIABLE_CREDENTIAL_TYPE.to_owned());
        credential.credential_subject.clear();
        assert_eq!(credential.validate(), Err(Error::NoSubjects));
    }

    #[test]
    fn rejects_inverted_validity_period() {
        let mut credential = example_credential().unwrap();
        credential.valid_from = Some(Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap());
        credential.valid_until = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
        assert_eq!(credential.validate(), Err(Error::InvalidValidityPeriod));
    }

    #[test]
    fn builder_requires_issuer() {
        let result = Credential::builder().subject(Subject::new()).build();
        assert_eq!(result.unwrap_err(), Error::MissingIssuer);
    }

    #[test]
    fn bitstring_status_roundtrip() {
        let mut credential = example_credential().unwrap();
        let entry = StatusListEntry::bitstring(
            "https://university.example/status/3#94567",
            "revocation",
            "94567",
            "https://university.example/status/3",
        );
        credential.credential_status = Some(serde_json::to_value(&entry).unwrap());

        assert_eq!(credential.bitstring_status().unwrap(), Some(entry));
        let json = serde_json::to_value(&credential).unwrap();
        assert_eq!(json["credentialStatus"]["type"], "BitstringStatusListEntry");
        assert_eq!(json["credentialStatus"]["statusListIndex"], "94567");
    }

    #[test]
    fn proof_roundtrip_with_details() {
        let created = Utc.with_ymd_and_hms(2026, 8, 23, 0, 0, 0).unwrap();
        let mut proof = Proof::eddsa_data_integrity(created, "https://university.example/keys/1");
        proof
            .details
            .insert("proofValue".into(), "z58DAdFfa9SkqZMVPxAQp7BQv".into());
        proof.expires = Some(Utc.with_ymd_and_hms(2027, 8, 23, 0, 0, 0).unwrap());

        let mut credential = example_credential().unwrap();
        credential.proof = Some(proof);

        let json = serde_json::to_value(&credential).unwrap();
        assert_eq!(json["proof"]["type"], "DataIntegrityProof");
        assert_eq!(json["proof"]["cryptosuite"], "eddsa-rdfc-2022");
        assert_eq!(json["proof"]["created"], "2026-08-23T00:00:00Z");
        let back: Credential = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.proof.as_ref().unwrap().details["proofValue"],
            "z58DAdFfa9SkqZMVPxAQp7BQv"
        );
    }
}
