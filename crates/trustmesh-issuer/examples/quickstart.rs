use trustmesh_credentials::{Credential, Subject};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::{verify_credential, CredentialIssuer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = CredentialIssuer::new(SigningKey::generate()?);

    let draft = Credential::builder()
        .context("https://www.w3.org/ns/credentials/examples/v2")
        .credential_type("ExampleAlumniCredential")
        .issuer(issuer.did().to_owned())
        .subject(
            Subject::new()
                .with_id("did:example:graduate-1")
                .with_claim("alumniOf", serde_json::json!("Example University")),
        )
        .build()?;

    let signed = issuer.issue(draft)?;
    let outcome = verify_credential(&signed)?;

    println!(
        "structural: {}, proof: {}",
        outcome.structural, outcome.proof
    );
    println!("{}", serde_json::to_string_pretty(&signed)?);
    Ok(())
}
