use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    Uri(String),
    Object { id: String },
}

impl Issuer {
    pub fn id(&self) -> &str {
        match self {
            Issuer::Uri(uri) => uri,
            Issuer::Object { id } => id,
        }
    }
}

impl From<&str> for Issuer {
    fn from(value: &str) -> Self {
        Issuer::Uri(value.to_owned())
    }
}

impl From<String> for Issuer {
    fn from(value: String) -> Self {
        Issuer::Uri(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_accepts_uri_and_object_forms() {
        let uri: Issuer = serde_json::from_str(r#""https://issuer.example""#).expect("valid");
        let object: Issuer =
            serde_json::from_str(r#"{"id": "https://issuer.example"}"#).expect("valid");
        assert_eq!(uri.id(), "https://issuer.example");
        assert_eq!(object.id(), "https://issuer.example");
        assert_eq!(uri, "https://issuer.example".into());
    }
}
