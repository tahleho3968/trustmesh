use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use trustmesh_credentials::{Credential, Subject};
use trustmesh_crypto::SigningKey;
use trustmesh_issuer::CredentialIssuer;
use trustmesh_verifier::{
    ProofStage, StatusStage, StructuralStage, TrustPolicyStage, VerificationPipeline,
};

#[derive(Clone)]
struct AppState {
    seed: [u8; 32],
    did: String,
}

#[derive(Deserialize)]
struct IssueRequest {
    subject_did: String,
    claims: serde_json::Value,
}

#[derive(Serialize)]
struct IssueResponse {
    credential: Credential,
}

#[derive(Deserialize)]
struct VerifyRequest {
    credential: Credential,
    #[serde(default)]
    trusted_issuers: Vec<String>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    stages: Vec<StageResult>,
}

#[derive(Serialize)]
struct StageResult {
    stage: String,
    verdict: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "trustmesh_api=info,tower_http=info".into()),
        )
        .init();

    let seed_hex = std::env::var("TRUSTMESH_SEED")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let key = SigningKey::generate().expect("OS randomness");
            let hex = hex::encode(key.to_bytes());
            eprintln!("No TRUSTMESH_SEED set; generated ephemeral key: {hex}");
            hex
        });

    let seed: [u8; 32] = hex::decode(&seed_hex)
        .expect("TRUSTMESH_SEED must be hex-encoded 32 bytes")
        .try_into()
        .expect("TRUSTMESH_SEED must be 32 bytes");

    let issuer = CredentialIssuer::new(SigningKey::from_bytes(&seed));
    eprintln!("Issuer DID: {}", issuer.did());

    let state = Arc::new(AppState {
        seed,
        did: issuer.did().to_owned(),
    });

    let static_dir: PathBuf = std::env::var("TRUSTMESH_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let manifest = std::env!("CARGO_MANIFEST_DIR");
            PathBuf::from(manifest).join("static")
        });

    let app = Router::new()
        .route("/health", get(health))
        .route("/issue", post(issue))
        .route("/verify", post(verify))
        .fallback_service(ServeDir::new(&static_dir).append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("static files: {}", static_dir.display());
    tracing::info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

async fn issue(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, ApiError> {
    let issuer = CredentialIssuer::new(SigningKey::from_bytes(&state.seed));

    let draft = Credential::builder()
        .context("https://www.w3.org/ns/credentials/examples/v2")
        .credential_type("ExampleAlumniCredential")
        .issuer(state.did.clone())
        .subject(
            Subject::new()
                .with_id(&req.subject_did)
                .with_claims(req.claims),
        )
        .build()
        .map_err(|e| ApiError::bad_request(format!("invalid draft: {e}")))?;

    let signed = issuer
        .issue(draft)
        .map_err(|e| ApiError::internal(format!("signing failed: {e}")))?;

    Ok(Json(IssueResponse { credential: signed }))
}

async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<VerifyResponse>, ApiError> {
    let mut pipeline = VerificationPipeline::new()
        .with_stage(Box::new(StructuralStage))
        .with_stage(Box::new(ProofStage::default()))
        .with_stage(Box::new(StatusStage));

    if !req.trusted_issuers.is_empty() {
        let allowed: Vec<&str> = req.trusted_issuers.iter().map(|s| s.as_str()).collect();
        pipeline = pipeline.with_stage(Box::new(TrustPolicyStage::allowing(allowed)));
    }

    let result = pipeline.verify(&req.credential);

    let stages = result
        .stages()
        .iter()
        .map(|o| StageResult {
            stage: o.stage.clone(),
            verdict: format!("{:?}", o.verdict).to_lowercase(),
        })
        .collect();

    Ok(Json(VerifyResponse {
        valid: result.valid(),
        stages,
    }))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({"error": self.message})),
        )
            .into_response()
    }
}
