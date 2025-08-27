// crates/engine/src/lib.rs

//! Public facade for the Que Engine.
//! Exposes a stable API and re-exports types for consumers (QueCloud, FFI).

pub mod adapters;
pub mod crypto;
pub mod domain;

use domain::error::{EngineResult};
pub use domain::types::{AssetRef, C2paConfig, C2paVerificationConfig, OutputTarget, EngineDefaults, IngredientConfig, FragmentedBmffConfig};
pub use domain::error::EngineError;

/// High-level helpers for the common "C2PA default" path.
/// Internally call the C2PA adapter. These give QueCloud a simple entrypoint.

pub fn sign_c2pa(cfg: C2paConfig) -> EngineResult<Option<Vec<u8>>> {
    adapters::c2pa::C2pa::generate(cfg)
}

pub fn sign_c2pa_bytes(
    bytes: &[u8],
    mut cfg: C2paConfig,
) -> EngineResult<Vec<u8>> {
    cfg.source = AssetRef::Bytes {
        data: bytes.to_vec(),
    };    
    cfg.output = OutputTarget::Memory;
    match adapters::c2pa::C2pa::generate(cfg)? {
        Some(buf) => Ok(buf),
        None => Err(EngineError::Config("memory output expected but none produced".into())),
    }
}

pub fn verify_c2pa(cfg: C2paVerificationConfig) -> EngineResult<VerificationResult> {
    adapters::c2pa::C2pa::verify(cfg)
}

/// Create an ingredient from an asset. If `output` is `Memory`, returns the serialized
/// `ingredient.json` bytes. If `Path(dir)`, writes files to the folder.
pub fn create_ingredient(cfg: IngredientConfig) -> EngineResult<Option<Vec<u8>>> {
    adapters::c2pa::C2pa::create_ingredient(cfg)
}

/// Embed a manifest into fragmented BMFF assets (init + fragments) using glob patterns.
#[cfg(all(feature = "c2pa", feature = "bmff"))]
pub fn generate_fragmented_bmff(cfg: FragmentedBmffConfig) -> EngineResult<()> {
    adapters::c2pa::C2pa::generate_fragmented_bmff(cfg)
}

// Re-exports for convenience
pub use crypto::signer::Signer;
pub use crypto::timestamper::Timestamper;
pub use domain::manifest_engine::ManifestEngine;
pub use domain::types::{SigAlg, VerifyMode, TrustPolicyConfig};
pub use domain::verify::VerificationResult;

// CAWG types (feature-gated)
#[cfg(feature = "cawg")]
pub use domain::cawg::{CawgIdentity, CawgVerifyOptions, CawgVerification};

/// Helper function to create CAWG X.509 identity configuration.
/// This provides a convenient way to set up CAWG identity with sensible defaults.
///
/// # Arguments
/// * `signer` - Certificate and private key for CAWG identity signing
/// * `referenced_assertions` - List of assertion labels that this identity should reference
///
/// # Returns
/// A `CawgIdentity` configured with Ed25519 algorithm and no timestamping
#[cfg(feature = "cawg")]
pub fn create_cawg_x509_config(
    signer: Signer,
    referenced_assertions: Vec<String>,
) -> CawgIdentity {
    CawgIdentity {
        signer,
        signing_alg: EngineDefaults::CAWG_SIGNING_ALGORITHM,
        referenced_assertions,
        timestamper: None,
    }
}

/// Helper function to create CAWG verification options.
/// This provides a convenient way to set up CAWG validation with sensible defaults.
///
/// # Arguments
/// * `validate` - Whether to run CAWG identity validation
/// * `require_valid_identity` - Whether to fail verification if CAWG identity is missing/invalid
///
/// # Returns
/// A `CawgVerifyOptions` configured with the specified validation settings
#[cfg(feature = "cawg")]
pub fn create_cawg_verify_options(
    validate: bool,
    require_valid_identity: bool,
) -> CawgVerifyOptions {
    CawgVerifyOptions {
        validate,
        require_valid_identity,
    }
}