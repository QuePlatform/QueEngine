// crates/engine/src/domain/types.rs

use std::path::PathBuf;

/// Supported signature algorithms for the engine. Mapped to c2pa internally.
#[derive(Debug, Clone, Copy)]
pub enum SigAlg {
    Es256,
    Es384,
    Ps256,
    Ed25519,
}

impl SigAlg {
    #[cfg(feature = "c2pa")]
    pub fn to_c2pa(self) -> c2pa::SigningAlg {
        match self {
            SigAlg::Es256 => c2pa::SigningAlg::Es256,
            SigAlg::Es384 => c2pa::SigningAlg::Es384,
            SigAlg::Ps256 => c2pa::SigningAlg::Ps256,
            SigAlg::Ed25519 => c2pa::SigningAlg::Ed25519,
        }
    }
}

/// Where verification output should be focused.
#[derive(Debug, Clone, Copy)]
pub enum VerifyMode {
    Summary,
    Info,
    Detailed,
    Tree,
}

/// A reference to an asset, which can be a path or in-memory bytes.
/// The `ext` field provides an optional file extension hint for byte-based
/// assets, which can help the C2PA library determine the content type.
#[derive(Debug, Clone)]
pub enum AssetRef {
    Path(PathBuf),
    Bytes {
        data: Vec<u8>,
        ext: Option<String>,
    },
}

/// A target for the output of a generation operation.
#[derive(Debug, Clone)]
pub enum OutputTarget {
    Path(PathBuf),
    Memory,
}

/// Configuration for C2PA generation.
#[derive(Debug, Clone)]
pub struct C2paConfig {
    pub source: AssetRef,
    pub output: OutputTarget,
    pub manifest_definition: Option<String>,
    pub parent: Option<AssetRef>,
    /// Optional base directory for resolving resources in a parent ingredient
    /// when the parent is provided as in-memory bytes.
    pub parent_base_dir: Option<PathBuf>,
    pub signer: crate::crypto::signer::Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<crate::crypto::timestamper::Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    /// Optional trust policy to apply when verifying immediately after signing.
    /// Mirrors options supported by the verify API.
    pub trust_policy: Option<TrustPolicyConfig>,
    pub skip_post_sign_validation: bool,
}

/// Configuration for C2PA verification.
#[derive(Debug, Clone)]
pub struct C2paVerificationConfig {
    pub source: AssetRef, // Changed from PathBuf to AssetRef
    pub mode: VerifyMode,
    pub policy: Option<TrustPolicyConfig>,
    pub allow_remote_manifests: bool,
}

/// Trust policy configuration, modeled after c2patool trust settings but
/// using raw bytes to avoid I/O in the engine.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicyConfig {
    /// PEM trust anchors data (concatenated PEMs)
    pub anchors: Option<Vec<u8>>,
    /// Allowed list of specific signing certificates (PEM)
    pub allowed_list: Option<Vec<u8>>,
    /// Allowed EKUs in OID dot notation
    pub allowed_ekus: Option<Vec<String>>,
}

/// Configuration for building an Ingredient from an asset.
#[derive(Debug, Clone)]
pub struct IngredientConfig {
    pub source: AssetRef,
    /// If Path(dir), write a folder with resources and an `ingredient.json` file.
    /// If Memory, return the serialized `ingredient.json` bytes.
    pub output: OutputTarget,
}

/// Configuration for generating a manifest into fragmented BMFF content.
#[derive(Debug, Clone)]
pub struct FragmentedBmffConfig {
    pub init_glob: PathBuf,
    pub fragments_glob: PathBuf,
    pub output_dir: PathBuf,

    /// Manifest definition JSON string (same semantics as `C2paConfig`).
    pub manifest_definition: Option<String>,
    pub signer: crate::crypto::signer::Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<crate::crypto::timestamper::Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    pub skip_post_sign_validation: bool,
}