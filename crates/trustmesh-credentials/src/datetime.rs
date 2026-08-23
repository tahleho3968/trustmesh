use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// Single source of truth for wire-format timestamps (RFC 3339, UTC, `Z`).
pub fn to_rfc3339(value: &DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

pub fn serialize<S>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&to_rfc3339(value))
}

pub fn serialize_optional<S>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(dt) => serializer.serialize_some(dt),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

pub fn deserialize_optional<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        None => Ok(None),
        Some(raw) => parse(raw).map(Some).map_err(serde::de::Error::custom),
    }
}

fn parse(raw: String) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(&raw).map(|dt| dt.with_timezone(&Utc))
}
