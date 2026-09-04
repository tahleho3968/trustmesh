use super::{Error, BASE_CONTEXT, VERIFIABLE_PRESENTATION_TYPE};
use crate::proof::Proof;
use crate::Context;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<Context>,

    #[serde(rename = "type")]
    pub types: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifiable_credential: Vec<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,

    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extensions: Map<String, Value>,
}

impl VerifiablePresentation {
    pub fn builder() -> PresentationBuilder {
        PresentationBuilder::default()
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self.context.first() {
            Some(Context::Url(url)) if url == BASE_CONTEXT => {}
            _ => return Err(Error::MissingBaseContext),
        }

        if !self
            .types
            .iter()
            .any(|t| t == VERIFIABLE_PRESENTATION_TYPE)
        {
            return Err(Error::MissingBaseType);
        }

        if self.verifiable_credential.is_empty() {
            return Err(Error::NoCredentials);
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct PresentationBuilder {
    context: Vec<Context>,
    types: Vec<String>,
    id: Option<String>,
    holder: Option<String>,
    credentials: Vec<Value>,
}

impl PresentationBuilder {
    pub fn context(mut self, context: impl Into<Context>) -> Self {
        self.context.push(context.into());
        self
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn presentation_type(mut self, type_: impl Into<String>) -> Self {
        let type_ = type_.into();
        if !self.types.contains(&type_) {
            self.types.push(type_);
        }
        self
    }

    pub fn holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = Some(holder.into());
        self
    }

    pub fn credential(mut self, credential: Value) -> Self {
        self.credentials.push(credential);
        self
    }

    pub fn build(self) -> Result<VerifiablePresentation, Error> {
        let mut context = self.context;
        if !matches!(context.first(), Some(Context::Url(url)) if url == BASE_CONTEXT) {
            context.insert(0, BASE_CONTEXT.into());
        }

        let mut types = self.types;
        if !types
            .iter()
            .any(|t| t == VERIFIABLE_PRESENTATION_TYPE)
        {
            types.insert(0, VERIFIABLE_PRESENTATION_TYPE.to_owned());
        }

        let presentation = VerifiablePresentation {
            context,
            types,
            id: self.id,
            holder: self.holder,
            verifiable_credential: self.credentials,
            proof: None,
            extensions: Map::new(),
        };
        presentation.validate()?;
        Ok(presentation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_presentation() -> Result<VerifiablePresentation, Error> {
        VerifiablePresentation::builder()
            .context("https://www.w3.org/ns/credentials/examples/v2")
            .presentation_type("CredentialManagerPresentation")
            .holder("did:example:alice")
            .credential(Value::String("http://university.example/credentials/3732".into()))
            .build()
    }

    #[test]
    fn builder_applies_required_defaults() {
        let presentation = example_presentation().expect("valid presentation");
        assert_eq!(presentation.context[0], BASE_CONTEXT.into());
        assert_eq!(presentation.types[0], VERIFIABLE_PRESENTATION_TYPE);
        assert!(presentation.validate().is_ok());
        assert!(presentation.proof.is_none());
    }

    #[test]
    fn serializes_with_spec_field_names() {
        let json = serde_json::to_value(example_presentation().unwrap()).unwrap();
        assert_eq!(json["@context"][0], BASE_CONTEXT);
        assert_eq!(json["type"][0], VERIFIABLE_PRESENTATION_TYPE);
        assert_eq!(json["holder"], "did:example:alice");
        assert_eq!(
            json["verifiableCredential"][0],
            "http://university.example/credentials/3732"
        );
        assert!(json.get("proof").is_none());
    }

    #[test]
    fn rejects_missing_base_context_or_type_or_credentials() {
        let mut presentation = example_presentation().unwrap();
        presentation.context.clear();
        assert_eq!(presentation.validate(), Err(Error::MissingBaseContext));

        presentation.context.push(BASE_CONTEXT.into());
        presentation.types.retain(|t| t != VERIFIABLE_PRESENTATION_TYPE);
        assert_eq!(presentation.validate(), Err(Error::MissingBaseType));

        presentation
            .types
            .insert(0, VERIFIABLE_PRESENTATION_TYPE.to_owned());
        presentation.verifiable_credential.clear();
        assert_eq!(presentation.validate(), Err(Error::NoCredentials));
    }
}
