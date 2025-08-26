use std::path::PathBuf;
use crate::crypto::signer::Signer;
use crate::crypto::timestamper::Timestamper;

use super::core::{SigAlg, VerifyMode, OutputTarget};
use super::asset::AssetRef;
use super::trust::TrustPolicyConfig;

/// Centralized defaults for the QueEngine.
/// All opinionated defaults should be defined here for consistency.
pub struct EngineDefaults;

impl EngineDefaults {
    // Security defaults
    pub const ALLOW_INSECURE_HTTP: Option<bool> = None; // Secure default: HTTPS only
    pub const ALLOW_REMOTE_MANIFESTS: bool = false; // Secure default: no network fetches
    pub const INCLUDE_CERTIFICATES: Option<bool> = None; // Privacy default: no certs included
    pub const EMBED_MANIFESTS: bool = true; // Standard C2PA behavior
    pub const SKIP_POST_SIGN_VALIDATION: bool = false; // Quality assurance default

    // Performance defaults
    pub const SIGNING_ALGORITHM: SigAlg = SigAlg::Es256; // Best compatibility
    pub const VERIFICATION_MODE: VerifyMode = VerifyMode::Summary; // Fastest
    pub const OUTPUT_TARGET: OutputTarget = OutputTarget::Memory; // API convenience

    // Feature defaults
    pub const HAS_TRUST_POLICY: Option<TrustPolicyConfig> = None; // Bring-your-own-trust
    pub const HAS_TIMESTAMPER: Option<Timestamper> = None; // Cost control
    pub const HAS_MANIFEST_DEFINITION: Option<String> = None; // Use built-in
    pub const HAS_PARENT: Option<AssetRef> = None; // No parent by default
    pub const HAS_PARENT_BASE_DIR: Option<PathBuf> = None; // No base dir override
    pub const HAS_REMOTE_MANIFEST_URL: Option<String> = None; // No remote URL
}

/// Configuration for C2PA generation.
#[derive(Debug)]
pub struct C2paConfig {
    pub source: AssetRef,
    pub output: OutputTarget,
    pub manifest_definition: Option<String>,
    pub parent: Option<AssetRef>,
    /// Optional base directory for resolving resources in a parent ingredient
    /// when the parent is provided as in-memory bytes.
    pub parent_base_dir: Option<PathBuf>,
    pub signer: Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    /// Optional trust policy to apply when verifying immediately after signing.
    /// Mirrors options supported by the verify API.
    pub trust_policy: Option<TrustPolicyConfig>,
    pub skip_post_sign_validation: bool,
    /// Opt-in: allow insecure HTTP for remote manifest URL (requires feature)
    pub allow_insecure_remote_http: Option<bool>,
}

/// Configuration for C2PA verification.
#[derive(Debug)]
pub struct C2paVerificationConfig {
    pub source: AssetRef, // Changed from PathBuf to AssetRef
    pub mode: VerifyMode,
    pub policy: Option<TrustPolicyConfig>,
    pub allow_remote_manifests: bool,
    /// Opt-in: include signing certificates in result
    pub include_certificates: Option<bool>,
}

impl Default for C2paVerificationConfig {
    fn default() -> Self {
        Self {
            source: AssetRef::Path(PathBuf::new()), // Note: AssetRef::Path is the safe default for most file operations
            mode: EngineDefaults::VERIFICATION_MODE,
            policy: EngineDefaults::HAS_TRUST_POLICY,
            allow_remote_manifests: EngineDefaults::ALLOW_REMOTE_MANIFESTS,
            include_certificates: EngineDefaults::INCLUDE_CERTIFICATES,
        }
    }
}

impl C2paConfig {
    /// Secure opinionated defaults; caller supplies source and signer.
    pub fn secure_default(source: AssetRef, signer: Signer, signing_alg: SigAlg) -> Self {
        Self {
            source,
            output: EngineDefaults::OUTPUT_TARGET,
            manifest_definition: EngineDefaults::HAS_MANIFEST_DEFINITION,
            parent: EngineDefaults::HAS_PARENT,
            parent_base_dir: EngineDefaults::HAS_PARENT_BASE_DIR,
            signer,
            signing_alg,
            timestamper: EngineDefaults::HAS_TIMESTAMPER,
            remote_manifest_url: EngineDefaults::HAS_REMOTE_MANIFEST_URL,
            embed: EngineDefaults::EMBED_MANIFESTS,
            trust_policy: EngineDefaults::HAS_TRUST_POLICY,
            skip_post_sign_validation: EngineDefaults::SKIP_POST_SIGN_VALIDATION,
            allow_insecure_remote_http: EngineDefaults::ALLOW_INSECURE_HTTP,
        }
    }
}

impl C2paVerificationConfig {
    /// Secure opinionated defaults; caller supplies source.
    pub fn secure_default(source: AssetRef) -> Self {
        Self {
            source,
            mode: EngineDefaults::VERIFICATION_MODE,
            policy: EngineDefaults::HAS_TRUST_POLICY,
            allow_remote_manifests: EngineDefaults::ALLOW_REMOTE_MANIFESTS,
            include_certificates: EngineDefaults::INCLUDE_CERTIFICATES,
        }
    }
}

/// Configuration for building an Ingredient from an asset.
#[derive(Debug)]
pub struct IngredientConfig {
    pub source: AssetRef,
    /// If Path(dir), write a folder with resources and an `ingredient.json` file.
    /// If Memory, return the serialized `ingredient.json` bytes.
    pub output: OutputTarget,
}

impl IngredientConfig {
    /// Secure opinionated defaults; caller supplies source.
    pub fn secure_default(source: AssetRef) -> Self {
        Self {
            source,
            output: EngineDefaults::OUTPUT_TARGET,
        }
    }
}

/// Configuration for generating a manifest into fragmented BMFF content.
#[derive(Debug, Clone)]
pub struct FragmentedBmffConfig {
    pub init_glob: PathBuf,
    pub fragments_glob: PathBuf,
    pub output_dir: PathBuf,

    /// Manifest definition JSON string (same semantics as `C2paConfig`).
    pub manifest_definition: Option<String>,
    pub signer: Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    pub skip_post_sign_validation: bool,
    /// Opt-in: allow insecure HTTP for remote manifest URL (requires feature)
    pub allow_insecure_remote_http: Option<bool>,
}

impl FragmentedBmffConfig {
    /// Secure opinionated defaults; caller supplies required fields.
    pub fn secure_default(
        init_glob: PathBuf,
        fragments_glob: PathBuf,
        output_dir: PathBuf,
        signer: Signer,
        signing_alg: SigAlg
    ) -> Self {
        Self {
            init_glob,
            fragments_glob,
            output_dir,
            manifest_definition: EngineDefaults::HAS_MANIFEST_DEFINITION,
            signer,
            signing_alg,
            timestamper: EngineDefaults::HAS_TIMESTAMPER,
            remote_manifest_url: EngineDefaults::HAS_REMOTE_MANIFEST_URL,
            embed: EngineDefaults::EMBED_MANIFESTS,
            skip_post_sign_validation: EngineDefaults::SKIP_POST_SIGN_VALIDATION,
            allow_insecure_remote_http: EngineDefaults::ALLOW_INSECURE_HTTP,
        }
    }
}
