use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Subject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(flatten)]
    pub claims: Map<String, Value>,
}

impl Subject {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.claims.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_roundtrips_claims() {
        let subject = Subject::new()
            .with_id("did:example:123")
            .with_claim("alumniOf", Value::Bool(true));
        let json = serde_json::to_value(&subject).expect("serializable");
        assert_eq!(json["id"], "did:example:123");
        assert_eq!(json["alumniOf"], true);
        let back: Subject = serde_json::from_value(json).expect("deserializable");
        assert_eq!(back, subject);
    }
}
