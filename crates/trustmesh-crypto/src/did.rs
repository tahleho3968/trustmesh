use std::collections::HashMap;

use crate::VerifyingKey;

const DID_KEY_PREFIX: &str = "did:key:";

/// Errors specific to DID resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidError {
    /// The DID method is not supported by this resolver.
    UnsupportedMethod(String),
    /// The DID string is malformed.
    Malformed(String),
    /// The verification method was not found in the DID document.
    VerificationMethodNotFound(String),
    /// The verification method type is not supported.
    UnsupportedKeyType(String),
    /// The public key encoding is invalid.
    InvalidPublicKey(String),
}

impl std::fmt::Display for DidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidError::UnsupportedMethod(m) => write!(f, "unsupported DID method: {m}"),
            DidError::Malformed(did) => write!(f, "malformed DID: {did}"),
            DidError::VerificationMethodNotFound(id) => {
                write!(f, "verification method not found: {id}")
            }
            DidError::UnsupportedKeyType(t) => write!(f, "unsupported key type: {t}"),
            DidError::InvalidPublicKey(msg) => write!(f, "invalid public key: {msg}"),
        }
    }
}

impl std::error::Error for DidError {}

/// Resolves a DID to a public key for signature verification.
///
/// Implementations handle specific DID methods (`did:key`, `did:web`, etc.).
/// All resolution is synchronous — callers pre-fetch any external resources
/// (DID documents, status lists) and supply them to the resolver.
pub trait DidResolver: Send + Sync {
    /// Returns the DID methods this resolver supports (e.g., `["key"]`).
    fn supported_methods(&self) -> &[&str];

    /// Resolves a `verificationMethod` URL or DID string to a public key.
    ///
    /// The input may be:
    /// - A full `verificationMethod` URL: `did:key:z6Mk...#z6Mk...`
    /// - A bare DID: `did:key:z6Mk...`
    fn resolve(&self, did: &str) -> Result<VerifyingKey, DidError>;
}

/// Resolves `did:key` DIDs by decoding the embedded public key.
///
/// This is the simplest resolver — `did:key` DIDs are self-certifying;
/// the public key IS the DID. No external resolution is needed.
pub struct DidKeyResolver;

impl DidResolver for DidKeyResolver {
    fn supported_methods(&self) -> &[&str] {
        &["key"]
    }

    fn resolve(&self, did: &str) -> Result<VerifyingKey, DidError> {
        let rest = did
            .strip_prefix(DID_KEY_PREFIX)
            .ok_or_else(|| DidError::UnsupportedMethod(extract_method(did)))?;

        let multikey = rest.split('#').next().unwrap_or(rest);
        VerifyingKey::from_multikey(multikey)
            .map_err(|_| DidError::InvalidPublicKey(multikey.to_owned()))
    }
}

/// Resolves `did:web` DIDs using pre-fetched DID documents.
///
/// Callers fetch DID documents out-of-band (e.g., from
/// `https://example.com/.well-known/did.json`) and supply them here.
/// The resolver extracts the verification method's public key from the
/// document.
pub struct DidWebResolver {
    documents: HashMap<String, serde_json::Value>,
}

impl DidWebResolver {
    /// Creates a resolver with pre-fetched DID documents.
    ///
    /// Keys are DID strings (e.g., `"did:web:example.com"`); values are the
    /// parsed DID documents.
    pub fn new(documents: HashMap<String, serde_json::Value>) -> Self {
        Self { documents }
    }
}

impl DidResolver for DidWebResolver {
    fn supported_methods(&self) -> &[&str] {
        &["web"]
    }

    fn resolve(&self, did: &str) -> Result<VerifyingKey, DidError> {
        let base_did = did.split('#').next().unwrap_or(did);

        let doc = self
            .documents
            .get(base_did)
            .ok_or_else(|| DidError::Malformed(format!("no DID document for {base_did}")))?;

        // If the input has a fragment, find the specific verification method.
        let vm_id = did.split('#').nth(1).map(|f| format!("{base_did}#{f}"));

        let verification_methods = doc
            .get("verificationMethod")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                DidError::Malformed(format!(
                    "DID document for {base_did} has no verificationMethod array"
                ))
            })?;

        let vm = if let Some(ref target_id) = vm_id {
            verification_methods
                .iter()
                .find(|vm| vm.get("id").and_then(|id| id.as_str()) == Some(target_id.as_str()))
                .ok_or_else(|| DidError::VerificationMethodNotFound(target_id.clone()))?
        } else {
            verification_methods.first().ok_or_else(|| {
                DidError::Malformed(format!(
                    "DID document for {base_did} has no verification methods"
                ))
            })?
        };

        let key_type = vm.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");

        let multikey = match key_type {
            "Ed25519VerificationKey2020" => vm
                .get("publicKeyMultibase")
                .and_then(|k| k.as_str())
                .ok_or_else(|| {
                DidError::InvalidPublicKey(format!(
                    "verification method {key_type} has no publicKeyMultibase"
                ))
            })?,
            _ => return Err(DidError::UnsupportedKeyType(key_type.to_owned())),
        };

        VerifyingKey::from_multikey(multikey)
            .map_err(|_| DidError::InvalidPublicKey(multikey.to_owned()))
    }
}

/// A resolver that delegates to multiple method-specific resolvers.
pub struct CompositeResolver {
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl CompositeResolver {
    pub fn new(resolvers: Vec<Box<dyn DidResolver>>) -> Self {
        Self { resolvers }
    }
}

impl DidResolver for CompositeResolver {
    fn supported_methods(&self) -> &[&str] {
        // Composite doesn't have its own methods; delegation is dynamic.
        &[]
    }

    fn resolve(&self, did: &str) -> Result<VerifyingKey, DidError> {
        let method = extract_method(did);
        for resolver in &self.resolvers {
            if resolver.supported_methods().contains(&method.as_str()) {
                return resolver.resolve(did);
            }
        }
        Err(DidError::UnsupportedMethod(method))
    }
}

/// Extracts the DID method from a DID string.
///
/// `"did:key:z6Mk..."` → `"key"`, `"did:web:example.com"` → `"web"`.
fn extract_method(did: &str) -> String {
    did.split(':').nth(1).unwrap_or("unknown").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;

    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[test]
    fn did_key_resolves_full_verification_method() {
        let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let did = format!("did:key:{}#{}", key.multikey(), key.multikey());
        assert_eq!(DidKeyResolver.resolve(&did), Ok(key));
    }

    #[test]
    fn did_key_resolves_bare_did() {
        let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let did = format!("did:key:{}", key.multikey());
        assert_eq!(DidKeyResolver.resolve(&did), Ok(key));
    }

    #[test]
    fn did_key_rejects_non_key_method() {
        assert_eq!(
            DidKeyResolver.resolve("did:web:example.com"),
            Err(DidError::UnsupportedMethod("web".into()))
        );
    }

    #[test]
    fn did_key_rejects_invalid_multikey() {
        assert_eq!(
            DidKeyResolver.resolve("did:key:zInvalidMultikey"),
            Err(DidError::InvalidPublicKey("zInvalidMultikey".into()))
        );
    }

    #[test]
    fn did_web_resolves_with_fragment() {
        let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": key.multikey()
            }]
        });
        let resolver = DidWebResolver::new(HashMap::from([("did:web:example.com".into(), doc)]));

        assert_eq!(resolver.resolve("did:web:example.com#key-1"), Ok(key));
    }

    #[test]
    fn did_web_resolves_without_fragment() {
        let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#primary",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": key.multikey()
            }]
        });
        let resolver = DidWebResolver::new(HashMap::from([("did:web:example.com".into(), doc)]));

        assert_eq!(resolver.resolve("did:web:example.com"), Ok(key));
    }

    #[test]
    fn did_web_rejects_missing_document() {
        let resolver = DidWebResolver::new(HashMap::new());
        assert!(matches!(
            resolver.resolve("did:web:unknown.com"),
            Err(DidError::Malformed(_))
        ));
    }

    #[test]
    fn did_web_rejects_unknown_fragment() {
        let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "publicKeyMultibase": key.multikey()
            }]
        });
        let resolver = DidWebResolver::new(HashMap::from([("did:web:example.com".into(), doc)]));
        assert!(matches!(
            resolver.resolve("did:web:example.com#nonexistent"),
            Err(DidError::VerificationMethodNotFound(_))
        ));
    }

    #[test]
    fn did_web_rejects_unsupported_key_type() {
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key-1",
                "type": "RsaVerificationKey2020",
                "publicKeyMultibase": "zFakeKey"
            }]
        });
        let resolver = DidWebResolver::new(HashMap::from([("did:web:example.com".into(), doc)]));
        assert!(matches!(
            resolver.resolve("did:web:example.com"),
            Err(DidError::UnsupportedKeyType(_))
        ));
    }

    #[test]
    fn composite_delegates_to_matching_resolver() {
        let key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#k",
                "type": "Ed25519VerificationKey2020",
                "publicKeyMultibase": key.multikey()
            }]
        });
        let composite = CompositeResolver::new(vec![
            Box::new(DidKeyResolver),
            Box::new(DidWebResolver::new(HashMap::from([(
                "did:web:example.com".into(),
                doc,
            )]))),
        ]);

        assert_eq!(
            composite.resolve(&format!("did:key:{}", key.multikey())),
            Ok(key.clone())
        );
        assert_eq!(composite.resolve("did:web:example.com#k"), Ok(key));
    }

    #[test]
    fn composite_rejects_unsupported_method() {
        let composite = CompositeResolver::new(vec![Box::new(DidKeyResolver)]);
        assert!(matches!(
            composite.resolve("did:ion:abc123"),
            Err(DidError::UnsupportedMethod(_))
        ));
    }

    #[test]
    fn extract_method_parses_correctly() {
        assert_eq!(extract_method("did:key:z6Mk..."), "key");
        assert_eq!(extract_method("did:web:example.com"), "web");
        assert_eq!(extract_method("did:ion:abc"), "ion");
        assert_eq!(extract_method("not-a-did"), "unknown");
    }
}
