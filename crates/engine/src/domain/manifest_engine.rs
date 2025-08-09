// crates/engine/src/domain/manifest_engine.rs

use anyhow::Result;
use super::verify::VerificationResult;

/// Trait implemented by provenance backends (C2PA today, others later).
pub trait ManifestEngine {
    type Config;
    type VerificationConfig;
    type Artifact;

    fn generate(config: Self::Config) -> Result<Self::Artifact>;
    fn verify(config: Self::VerificationConfig) -> Result<VerificationResult>;
}