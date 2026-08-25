//! RFC 8785 (JSON Canonicalization Scheme) conformance suite.
//!
//! Canonicalization is the foundation of `eddsa-jcs-2022`: two implementations
//! that serialize differently cannot verify each other's signatures. These
//! tests pin `trustmesh_issuer::canonical::canonicalize` to the official
//! vectors so canonicalization drift is impossible to merge. See RFC 0004 and
//! `tests/vectors/rfc8785/README.md` for provenance.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use trustmesh_credentials::{Credential, Subject};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::canonical::canonicalize;
use trustmesh_issuer::{verify_credential, CredentialIssuer};

const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/rfc8785");

fn vector_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(Path::new(VECTORS_DIR).join("input"))
        .expect("vectors/rfc8785/input must exist")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(stem)
        .collect();
    names.sort();
    assert!(
        !names.is_empty(),
        "no conformance vectors found; tests/vectors is broken"
    );
    names
}

fn stem(path: PathBuf) -> String {
    path.file_stem()
        .expect("input file has a name")
        .to_string_lossy()
        .into_owned()
}

fn read_vector(name: &str, kind: &str) -> Vec<u8> {
    fs::read(
        Path::new(VECTORS_DIR)
            .join(kind)
            .join(format!("{name}.json")),
    )
    .unwrap_or_else(|error| panic!("read {kind}/{name}.json: {error}"))
}

#[test]
fn official_vectors_canonicalize_byte_for_byte() {
    for name in vector_names() {
        let input = read_vector(&name, "input");
        let expected = read_vector(&name, "output");

        let value: Value = serde_json::from_slice(&input)
            .unwrap_or_else(|error| panic!("{name}: input must parse: {error}"));
        let actual = canonicalize(&value)
            .unwrap_or_else(|error| panic!("{name}: canonicalization failed: {error}"));

        assert_eq!(
            actual, expected,
            "{name}: canonical form diverges from RFC 8785"
        );
    }
}

#[test]
fn canonicalization_is_idempotent() {
    for name in vector_names() {
        let value: Value =
            serde_json::from_slice(&read_vector(&name, "input")).expect("input parses");
        let once = canonicalize(&value).expect("first pass");
        let twice = canonicalize(
            &serde_json::from_slice::<Value>(&once).expect("canonical output reparses"),
        )
        .expect("second pass");
        assert_eq!(once, twice, "{name}: canonicalization must be idempotent");
    }
}

/// RFC 8785 sorts object names by UTF-16 code units, which puts astral-plane
/// characters (surrogate pairs, U+D800..=U+DFFF) *before* some BMP characters.
/// `weird.json` covers this implicitly; this test makes the rule explicit so a
/// serializer swap cannot silently regress it.
#[test]
fn astral_plane_keys_sort_by_utf16_code_units() {
    let value: Value = serde_json::from_str(r#"{"\ufb33":1,"\ud83d\ude02":2}"#).expect("parses");
    let canonical = String::from_utf8(canonicalize(&value).expect("canonicalizes")).unwrap();
    assert_eq!(canonical, r#"{"😂":2,"דּ":1}"#);
}

#[test]
fn issuance_and_verification_survive_conformance_stress_claims() {
    let issuer = CredentialIssuer::new(SigningKey::generate().expect("OS entropy"));
    let created = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 8, 25, 0, 0, 0).unwrap();

    let draft = Credential::builder()
        .context("https://www.w3.org/ns/credentials/examples/v2")
        .credential_type("JcsStressCredential")
        .issuer(issuer.did().to_owned())
        .subject(
            Subject::new()
                .with_id("did:example:jcs-stress")
                .with_claim("\u{20AC}", serde_json::json!("Euro Sign"))
                .with_claim("\u{1F602}", serde_json::json!("Smiley"))
                .with_claim("\u{FB33}", serde_json::json!("Dalet With Dagesh"))
                .with_claim("amount", serde_json::json!(1e30))
                .with_claim("ratio", serde_json::json!(0.002))
                .with_claim("</script>", serde_json::json!("Browser Challenge")),
        )
        .build()
        .expect("draft validates");

    let signed = issuer.issue_at(draft, created).expect("issues");

    let outcome = verify_credential(&signed).expect("verification runs");
    assert!(outcome.structural);
    assert!(
        outcome.proof,
        "sign→verify roundtrip must survive JCS edge cases"
    );
}
