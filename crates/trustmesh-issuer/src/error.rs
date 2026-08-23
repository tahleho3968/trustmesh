use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    AlreadyProven,
    IssuerMismatch,
    MissingProof,
    UnsupportedCryptosuite(String),
    InvalidVerificationMethod,
    MalformedProofValue,
    Serialization(String),
    Canonicalization(String),
    Verification,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyProven => write!(f, "credential already carries a proof"),
            Error::IssuerMismatch => write!(
                f,
                "credential issuer does not match the issuing key's did:key identifier"
            ),
            Error::MissingProof => write!(f, "credential carries no proof to verify"),
            Error::UnsupportedCryptosuite(suite) => {
                write!(f, "unsupported cryptosuite: {suite}")
            }
            Error::InvalidVerificationMethod => write!(
                f,
                "verificationMethod must be a did:key Ed25519 Multikey (did:key:z6Mk…#z6Mk…)"
            ),
            Error::MalformedProofValue => {
                write!(
                    f,
                    "proofValue must be multibase base58btc (`z…`) Ed25519 signature"
                )
            }
            Error::Serialization(msg) => write!(f, "serialization failed: {msg}"),
            Error::Canonicalization(msg) => write!(f, "canonicalization failed: {msg}"),
            Error::Verification => write!(f, "proof verification failed"),
        }
    }
}

impl std::error::Error for Error {}
