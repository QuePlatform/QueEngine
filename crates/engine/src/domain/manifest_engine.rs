// crates/engine/src/domain/manifest_engine.rs

use super::verify::VerificationResult;
use super::error::EngineResult;

/// Trait implemented by provenance backends (C2PA today, others later).
pub trait ManifestEngine {
    type Config;
    type VerificationConfig;
    type Artifact;

    fn generate(config: Self::Config) -> EngineResult<Self::Artifact>;
    fn verify(config: Self::VerificationConfig) -> EngineResult<VerificationResult>;
}