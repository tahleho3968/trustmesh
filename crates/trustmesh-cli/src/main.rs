use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use trustmesh_credentials::{Credential, VerifiablePresentation};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::{
    verify_presentation, CredentialIssuer, PresentationHolder,
};
use trustmesh_verifier::{
    ProofStage, StatusStage, StructuralStage, TrustPolicyStage, VerificationPipeline,
    VerificationStage,
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

    /// Create or verify a Verifiable Presentation
    Vp(Vp),
}

#[derive(Args)]
struct Vp {
    #[command(subcommand)]
    command: VpCommand,
}

#[derive(Subcommand)]
enum VpCommand {
    /// Wrap one or more credentials into a signed Verifiable Presentation
    Sign {
        /// Path to the holder's signing key (32-byte seed, hex-encoded)
        #[arg(long)]
        key: PathBuf,

        /// Paths to credential JSON files (repeatable)
        #[arg(long = "credential")]
        credentials: Vec<PathBuf>,

        /// Output file (defaults to stdout)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Verify a Verifiable Presentation and its embedded credentials
    Verify {
        /// Path to the presentation JSON
        #[arg(long)]
        presentation: PathBuf,

        /// Trusted issuer DIDs for embedded credentials (repeatable)
        #[arg(long = "trusted")]
        trusted_issuers: Vec<String>,
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
        Command::Vp(vp) => match vp.command {
            VpCommand::Sign { key, credentials, out } => cmd_vp_sign(key, credentials, out),
            VpCommand::Verify { presentation, trusted_issuers } => {
                cmd_vp_verify(presentation, trusted_issuers)
            }
        },
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

fn parse_seed(path: &PathBuf) -> Result<[u8; 32]> {
    let seed_hex = std::fs::read_to_string(path)
        .with_context(|| format!("reading key file {}", path.display()))?;
    let seed_bytes = hex::decode(seed_hex.trim()).context("key must be hex-encoded")?;
    seed_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be exactly 32 bytes"))
}

fn cmd_vp_sign(key: PathBuf, credentials: Vec<PathBuf>, out: Option<PathBuf>) -> Result<()> {
    let seed = parse_seed(&key)?;
    let holder = PresentationHolder::new(SigningKey::from_bytes(&seed));

    let mut builder = VerifiablePresentation::builder();
    for path in &credentials {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("reading credential {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&json).context("parsing credential JSON")?;
        builder = builder.credential(value);
    }
    let draft = builder.build().context("building presentation")?;

    let signed = holder.sign(draft).context("signing presentation")?;
    let output = serde_json::to_string_pretty(&signed).context("serializing presentation")?;

    match out {
        Some(path) => {
            std::fs::write(&path, &output)
                .with_context(|| format!("writing to {}", path.display()))?;
            eprintln!("Wrote presentation to {}", path.display());
        }
        None => println!("{output}"),
    }

    Ok(())
}

fn cmd_vp_verify(presentation: PathBuf, trusted_issuers: Vec<String>) -> Result<()> {
    let json = std::fs::read_to_string(&presentation)
        .with_context(|| format!("reading presentation {}", presentation.display()))?;
    let vp: VerifiablePresentation =
        serde_json::from_str(&json).context("parsing presentation JSON")?;

    let outcome = verify_presentation(&vp).context("verifying presentation")?;

    eprintln!("  {}  vp structural", ok(outcome.structural));
    eprintln!("  {}  vp proof", ok(outcome.proof));
    for (i, credit) in outcome.credential_results.iter().enumerate() {
        eprintln!("  {}  credential[{i}] structural", ok(credit.structural));
        eprintln!("  {}  credential[{i}] proof", ok(credit.proof));
    }

    if !trusted_issuers.is_empty() {
        let allowed: Vec<&str> = trusted_issuers.iter().map(|s| s.as_str()).collect();
        let policy = TrustPolicyStage::allowing(allowed);
        let mut all_trusted = true;
        let mut reasons: Vec<String> = Vec::new();
        for value in &vp.verifiable_credential {
            match serde_json::from_value::<trustmesh_credentials::Credential>(value.clone()) {
                Ok(credential) => {
                    let verdict =
                        policy.check(&trustmesh_verifier::VerificationContext::new(&credential));
                    match &verdict {
                        trustmesh_verifier::Verdict::Pass => {}
                        trustmesh_verifier::Verdict::Fail(r) => {
                            all_trusted = false;
                            reasons.push(r.clone());
                        }
                        trustmesh_verifier::Verdict::Inconclusive(r) => {
                            all_trusted = false;
                            reasons.push(r.clone());
                        }
                    }
                }
                Err(_) => {
                    all_trusted = false;
                    reasons.push("unable to parse embedded credential".to_owned());
                }
            }
        }
        if all_trusted {
            eprintln!("  ok    trust_policy");
        } else {
            eprintln!("  FAIL  trust_policy: {}", reasons.join("; "));
            std::process::exit(1);
        }
    }

    if outcome.valid() {
        eprintln!("\nPresentation is valid.");
        Ok(())
    } else {
        eprintln!("\nPresentation is INVALID.");
        std::process::exit(1);
    }
}

fn ok(good: bool) -> &'static str {
    if good { "ok" } else { "FAIL" }
}
