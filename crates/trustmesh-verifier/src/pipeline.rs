use serde::{Deserialize, Serialize};
use trustmesh_credentials::{BitstringStatusList, Credential};

/// Verdict of a single pipeline stage.
///
/// [`Verdict::Inconclusive`] exists so a stage can report "this credential
/// carries information I cannot check yet" (e.g. a status entry before
/// Bitstring Status List support lands) without pretending the check passed
/// or failed. Only [`Verdict::Fail`] makes a result invalid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Inconclusive(String),
    Fail(String),
}

impl Verdict {
    pub fn passed(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

/// Serializable outcome of one stage — the unit of verification logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageOutcome {
    pub stage: String,
    pub verdict: Verdict,
}

/// Result of running a credential through a pipeline.
///
/// `valid` is derived from the stage outcomes rather than stored, so a
/// deserialized log can never disagree with its own stages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    stages: Vec<StageOutcome>,
}

impl VerificationResult {
    pub(crate) fn new(stages: Vec<StageOutcome>) -> Self {
        Self { stages }
    }

    /// True when every stage passed. An `Inconclusive` stage is not a failure,
    /// but it also does not make the credential valid.
    pub fn valid(&self) -> bool {
        self.stages.iter().all(|outcome| outcome.verdict.passed())
    }

    pub fn stages(&self) -> &[StageOutcome] {
        &self.stages
    }

    /// Stage names in execution order, for quick logging and assertions.
    pub fn stage_names(&self) -> Vec<&str> {
        self.stages
            .iter()
            .map(|outcome| outcome.stage.as_str())
            .collect()
    }

    pub fn failures(&self) -> impl Iterator<Item = &StageOutcome> {
        self.stages
            .iter()
            .filter(|outcome| matches!(outcome.verdict, Verdict::Fail(_)))
    }
}

/// Everything a stage may inspect. Status lists are supplied by the caller
/// because fetching (and proof-checking) them is an I/O and trust decision
/// outside this crate; the context grows additively as later phases land.
pub struct VerificationContext<'a> {
    credential: &'a Credential,
    status_lists: Vec<BitstringStatusList>,
}

impl<'a> VerificationContext<'a> {
    pub fn new(credential: &'a Credential) -> Self {
        Self {
            credential,
            status_lists: Vec::new(),
        }
    }

    /// Supplies a fetched status list credential so the status stage can
    /// return real verdicts for entries pointing at it.
    pub fn with_status_list(mut self, status_list: BitstringStatusList) -> Self {
        self.status_lists.push(status_list);
        self
    }

    pub fn credential(&self) -> &Credential {
        self.credential
    }

    pub fn status_lists(&self) -> &[BitstringStatusList] {
        &self.status_lists
    }
}

/// One check in the pipeline. Implementations must be cheap, side-effect
/// free, and safe to share across threads.
pub trait VerificationStage: Send + Sync {
    fn name(&self) -> &'static str;

    fn check(&self, ctx: &VerificationContext<'_>) -> Verdict;
}

/// Ordered set of stages. Every stage runs even after earlier failures so a
/// caller gets the complete picture in one pass.
#[derive(Default)]
pub struct VerificationPipeline {
    stages: Vec<Box<dyn VerificationStage>>,
}

impl VerificationPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    /// The objective checks every verifier should run: structural validity,
    /// cryptographic proof, and credential status shape. Trust policy is
    /// deployment-specific and added explicitly by the caller.
    pub fn default_pipeline() -> Self {
        Self::new()
            .with_stage(Box::new(super::stages::StructuralStage))
            .with_stage(Box::new(super::stages::ProofStage))
            .with_stage(Box::new(super::stages::StatusStage))
    }

    pub fn with_stage(mut self, stage: Box<dyn VerificationStage>) -> Self {
        self.stages.push(stage);
        self
    }

    pub fn stage_names(&self) -> Vec<&'static str> {
        self.stages.iter().map(|stage| stage.name()).collect()
    }

    pub fn verify(&self, credential: &Credential) -> VerificationResult {
        let ctx = VerificationContext::new(credential);
        self.verify_with(&ctx)
    }

    /// Runs the pipeline against a pre-built context, for callers supplying
    /// fetched status lists (or future context additions).
    pub fn verify_with(&self, ctx: &VerificationContext<'_>) -> VerificationResult {
        let outcomes = self
            .stages
            .iter()
            .map(|stage| StageOutcome {
                stage: stage.name().to_owned(),
                verdict: stage.check(ctx),
            })
            .collect();
        VerificationResult::new(outcomes)
    }
}
