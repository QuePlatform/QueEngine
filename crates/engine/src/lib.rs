//! Public facade for the Que Engine.
//! Exposes a stable API and re-exports types for consumers (QueCloud, FFI).

pub mod adapters;
pub mod crypto;
pub mod domain;

use anyhow::Result;
use domain::types::{C2paConfig, C2paVerificationConfig};

/// High-level helpers for the common "C2PA default" path.
/// Internally call the C2PA adapter. These give QueCloud a simple entrypoint.

pub fn sign_c2pa(cfg: C2paConfig) -> Result<()> {
    adapters::c2pa::C2pa::generate(cfg)
}

pub fn verify_c2pa(cfg: C2paVerificationConfig) -> Result<VerificationResult> {
    adapters::c2pa::C2pa::verify(cfg)
}

// Re-exports for convenience
pub use crypto::signer::Signer;
pub use crypto::timestamper::Timestamper;
pub use domain::manifest_engine::ManifestEngine;
pub use domain::types::{SigAlg, VerifyMode};
pub use domain::verify::VerificationResult;