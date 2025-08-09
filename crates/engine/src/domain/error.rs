// crates/engine/src/domain/error.rs
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
  #[error("configuration: {0}")]
  Config(String),

  #[error(transparent)]
  Io(#[from] std::io::Error),

  #[error(transparent)]
  Json(#[from] serde_json::Error),

  #[cfg(feature = "bmff")]
  #[error(transparent)]
  Glob(#[from] glob::PatternError),

  #[cfg(feature = "c2pa")]
  #[error(transparent)]
  C2pa(#[from] c2pa::Error),

  #[error("feature not enabled: {0}")]
  Feature(&'static str),

  #[error("verification failed")]
  VerificationFailed,

  // Useful when we catch_unwind to avoid crossing FFI boundaries with panics.
  #[error("internal panic: {0}")]
  Panic(String),
}

pub type EngineResult<T> = Result<T, EngineError>;