// crates/engine/src/domain/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("C2PA error: {0}")]
    C2pa(String),

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Feature not enabled: {0}")]
    Feature(String),
}

// Allow `?` on anyhow::Result
impl From<anyhow::Error> for EngineError {
    fn from(err: anyhow::Error) -> Self {
        EngineError::C2pa(err.to_string())
    }
}

// Allow `?` on c2pa::Result
#[cfg(feature = "c2pa")]
impl From<c2pa::Error> for EngineError {
    fn from(err: c2pa::Error) -> Self {
        EngineError::C2pa(err.to_string())
    }
}

pub type EngineResult<T> = Result<T, EngineError>;