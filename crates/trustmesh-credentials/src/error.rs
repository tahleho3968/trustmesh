use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MissingBaseContext,
    MissingBaseType,
    MissingIssuer,
    NoSubjects,
    NoCredentials,
    InvalidValidityPeriod,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingBaseContext => write!(
                f,
                "first @context entry must be the string \"{}\"",
                crate::BASE_CONTEXT
            ),
            Error::MissingBaseType => write!(
                f,
                "\"type\" must include \"{}\"",
                crate::VERIFIABLE_CREDENTIAL_TYPE
            ),
            Error::MissingIssuer => write!(f, "credential must declare an issuer"),
            Error::NoSubjects => write!(f, "credential must have at least one subject"),
            Error::NoCredentials => {
                write!(f, "presentation must embed at least one verifiable credential")
            }
            Error::InvalidValidityPeriod => {
                write!(f, "validUntil must not be earlier than validFrom")
            }
        }
    }
}

impl std::error::Error for Error {}
