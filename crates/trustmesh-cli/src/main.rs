use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use trustmesh_credentials::Credential;
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::CredentialIssuer;
use trustmesh_verifier::{
    ProofStage, StatusStage, StructuralStage, TrustPolicyStage, VerificationPipeline,
};

#[derive(Parser)]
#[command(
    name = "trustmesh",
    about = "W3C Verifiable Credentials from the terminal"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair and print the DID
    Keygen,

    /// Issue a credential from a JSON draft
    Issue {
        /// Path to the signing key (32-byte seed, hex-encoded)
        #[arg(long)]
        key: PathBuf,

        /// Path to the credential draft JSON
        #[arg(long)]
        draft: PathBuf,

        /// Output file (defaults to stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify a credential
    Verify {
        /// Path to the credential JSON
        #[arg(long)]
        credential: PathBuf,

        /// Trusted issuer DIDs (repeatable)
        #[arg(long = "trusted")]
        trusted_issuers: Vec<String>,
    },

    /// Generate a QR code for a credential
    Qr {
        /// Path to the credential JSON
        #[arg(long)]
        credential: PathBuf,

        /// Base URL of the verifier (default: http://localhost:3000)
        #[arg(long, default_value = "http://localhost:3000")]
        url: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen => cmd_keygen(),
        Command::Issue { key, draft, out } => cmd_issue(key, draft, out),
        Command::Verify {
            credential,
            trusted_issuers,
        } => cmd_verify(credential, trusted_issuers),
        Command::Qr { credential, url } => cmd_qr(credential, url),
    }
}

fn cmd_keygen() -> Result<()> {
    let key = SigningKey::generate().context("generating key")?;
    let seed_hex = hex::encode(key.to_bytes());
    let issuer = CredentialIssuer::new(key);

    eprintln!("DID:          {}", issuer.did());
    eprintln!("Verification: {}", issuer.verification_method());
    println!("{seed_hex}");

    Ok(())
}

fn cmd_issue(key: PathBuf, draft: PathBuf, out: Option<PathBuf>) -> Result<()> {
    let seed_hex = std::fs::read_to_string(&key)
        .with_context(|| format!("reading key file {}", key.display()))?;
    let seed_bytes = hex::decode(seed_hex.trim()).context("key must be hex-encoded")?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be exactly 32 bytes"))?;

    let draft_json = std::fs::read_to_string(&draft)
        .with_context(|| format!("reading draft {}", draft.display()))?;
    let credential: Credential = serde_json::from_str(&draft_json).context("parsing draft JSON")?;

    let issuer = CredentialIssuer::new(SigningKey::from_bytes(&seed));
    let signed = issuer.issue(credential).context("signing credential")?;

    let json = serde_json::to_string_pretty(&signed).context("serializing credential")?;

    match out {
        Some(path) => {
            std::fs::write(&path, &json)
                .with_context(|| format!("writing to {}", path.display()))?;
            eprintln!("Wrote credential to {}", path.display());
        }
        None => println!("{json}"),
    }

    Ok(())
}

fn cmd_verify(credential: PathBuf, trusted_issuers: Vec<String>) -> Result<()> {
    let json = std::fs::read_to_string(&credential)
        .with_context(|| format!("reading credential {}", credential.display()))?;
    let credential: Credential = serde_json::from_str(&json).context("parsing credential JSON")?;

    let mut pipeline = VerificationPipeline::new()
        .with_stage(Box::new(StructuralStage))
        .with_stage(Box::new(ProofStage::default()))
        .with_stage(Box::new(StatusStage));

    if !trusted_issuers.is_empty() {
        let allowed: Vec<&str> = trusted_issuers.iter().map(|s| s.as_str()).collect();
        pipeline = pipeline.with_stage(Box::new(TrustPolicyStage::allowing(allowed)));
    }

    let result = pipeline.verify(&credential);

    for outcome in result.stages() {
        let icon = match &outcome.verdict {
            trustmesh_verifier::Verdict::Pass => "ok",
            trustmesh_verifier::Verdict::Fail(_) => "FAIL",
            trustmesh_verifier::Verdict::Inconclusive(_) => "??",
        };
        eprint!("  {icon:4}  {}", outcome.stage);
        match &outcome.verdict {
            trustmesh_verifier::Verdict::Pass => eprintln!(),
            trustmesh_verifier::Verdict::Fail(reason) => eprintln!(": {reason}"),
            trustmesh_verifier::Verdict::Inconclusive(reason) => eprintln!(": {reason}"),
        }
    }

    if result.valid() {
        eprintln!("\nCredential is valid.");
        Ok(())
    } else {
        eprintln!("\nCredential is INVALID.");
        std::process::exit(1);
    }
}

fn cmd_qr(credential: PathBuf, base_url: String) -> Result<()> {
    let json = std::fs::read_to_string(&credential)
        .with_context(|| format!("reading credential {}", credential.display()))?;

    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    let url = format!("{base_url}/?c={encoded}");

    let code = qrcode::QrCode::new(url.as_bytes()).context("generating QR code")?;

    let qr = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();

    println!("{qr}");

    eprintln!("\nURL length: {} bytes", url.len());

    Ok(())
}
