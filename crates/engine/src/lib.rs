// crates/engine/src/lib.rs

//! Public facade for the Que Engine.
//! Exposes a stable API and re-exports types for consumers (QueCloud, FFI).

pub mod adapters;
pub mod crypto;
pub mod domain;

use anyhow::Result;
use domain::types::{AssetRef, C2paConfig, C2paVerificationConfig, OutputTarget};

/// High-level helpers for the common "C2PA default" path.
/// Internally call the C2PA adapter. These give QueCloud a simple entrypoint.

pub fn sign_c2pa(cfg: C2paConfig) -> Result<Option<Vec<u8>>> {
    adapters::c2pa::C2pa::generate(cfg)
}

pub fn sign_c2pa_bytes(
    bytes: &[u8],
    mut cfg: C2paConfig,
) -> Result<Vec<u8>> {
    cfg.source = AssetRef::Bytes(bytes.to_vec());
    cfg.output = OutputTarget::Memory;
    adapters::c2pa::C2pa::generate(cfg).map(|o| o.unwrap_or_default())
}

pub fn verify_c2pa(cfg: C2paVerificationConfig) -> Result<VerificationResult> {
    adapters::c2pa::C2pa::verify(cfg)
}

/// Create an ingredient from an asset. If `output` is `Memory`, returns the serialized
/// `ingredient.json` bytes. If `Path(dir)`, writes files to the folder.
pub fn create_ingredient(cfg: IngredientConfig) -> Result<Option<Vec<u8>>> {
    adapters::c2pa::C2pa::create_ingredient(cfg)
}

/// Embed a manifest into fragmented BMFF assets (init + fragments) using glob patterns.
pub fn generate_fragmented_bmff(cfg: FragmentedBmffConfig) -> Result<()> {
    adapters::c2pa::C2pa::generate_fragmented_bmff(cfg)
}

// Re-exports for convenience
pub use crypto::signer::Signer;
pub use crypto::timestamper::Timestamper;
pub use domain::manifest_engine::ManifestEngine;
pub use domain::types::{SigAlg, VerifyMode, TrustPolicyConfig, IngredientConfig, FragmentedBmffConfig};
pub use domain::verify::VerificationResult;