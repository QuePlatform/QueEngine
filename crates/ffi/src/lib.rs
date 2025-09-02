use std::path::PathBuf;

use que_engine::crypto::signer::Signer;
use que_engine::crypto::timestamper::Timestamper;
use que_engine::domain::error::EngineError;
use que_engine::domain::types as dt;
use que_engine::{sign_c2pa, verify_c2pa, create_ingredient};

// (Keep VerifyOptions defined once later for deprecated helper)

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{message}")]
    Generic { message: String },
}

impl From<EngineError> for FfiError {
    fn from(e: EngineError) -> Self {
        FfiError::Generic {
            message: e.to_string(),
        }
    }
}

// ===== FFI types mirroring the public Rust API (FFI-friendly) =====

#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum FfiSigAlg { Es256, Es384, Ps256, Ed25519 }

impl From<FfiSigAlg> for dt::SigAlg {
    fn from(v: FfiSigAlg) -> Self {
        match v { FfiSigAlg::Es256 => dt::SigAlg::Es256, FfiSigAlg::Es384 => dt::SigAlg::Es384, FfiSigAlg::Ps256 => dt::SigAlg::Ps256, FfiSigAlg::Ed25519 => dt::SigAlg::Ed25519 }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum FfiVerifyMode { Summary, Info, Detailed, Tree }

impl From<FfiVerifyMode> for dt::VerifyMode {
    fn from(v: FfiVerifyMode) -> Self {
        match v { FfiVerifyMode::Summary => dt::VerifyMode::Summary, FfiVerifyMode::Info => dt::VerifyMode::Info, FfiVerifyMode::Detailed => dt::VerifyMode::Detailed, FfiVerifyMode::Tree => dt::VerifyMode::Tree }
    }
}

#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiAssetRef { Path(String), Bytes(Vec<u8>) }

impl From<FfiAssetRef> for dt::AssetRef {
    fn from(v: FfiAssetRef) -> Self {
        match v {
            FfiAssetRef::Path(p) => dt::AssetRef::Path(PathBuf::from(p)),
            FfiAssetRef::Bytes(b) => dt::AssetRef::Bytes { data: b },
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiOutputTarget { Path(String), Memory }

impl From<FfiOutputTarget> for dt::OutputTarget {
    fn from(v: FfiOutputTarget) -> Self {
        match v { FfiOutputTarget::Path(p) => dt::OutputTarget::Path(PathBuf::from(p)), FfiOutputTarget::Memory => dt::OutputTarget::Memory }
    }
}

#[derive(uniffi::Enum, Debug, Clone)]
pub enum FfiTimestamper { Digicert, Custom(String) }

impl From<FfiTimestamper> for Timestamper {
    fn from(v: FfiTimestamper) -> Self {
        match v { FfiTimestamper::Digicert => Timestamper::Digicert, FfiTimestamper::Custom(u) => Timestamper::Custom(u) }
    }
}

#[derive(uniffi::Record, Debug, Clone, Copy)]
pub struct FfiLimitsConfig {
    pub max_in_memory_asset_size: u64,
    pub max_in_memory_output_size: u64,
    pub max_stream_copy_size: u64,
    pub max_stream_read_timeout_secs: u64,
}

impl From<FfiLimitsConfig> for dt::LimitsConfig {
    fn from(v: FfiLimitsConfig) -> Self {
        dt::LimitsConfig {
            max_in_memory_asset_size: v.max_in_memory_asset_size as usize,
            max_in_memory_output_size: v.max_in_memory_output_size as usize,
            max_stream_copy_size: v.max_stream_copy_size as usize,
            max_stream_read_timeout_secs: v.max_stream_read_timeout_secs,
        }
    }
}

impl FfiLimitsConfig {
    pub fn defaults() -> Self {
        let d = dt::LimitsConfig::defaults();
        Self {
            max_in_memory_asset_size: d.max_in_memory_asset_size as u64,
            max_in_memory_output_size: d.max_in_memory_output_size as u64,
            max_stream_copy_size: d.max_stream_copy_size as u64,
            max_stream_read_timeout_secs: d.max_stream_read_timeout_secs,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiTrustPolicyConfig {
    pub anchors: Option<Vec<u8>>,          // raw trust anchors (DER or bundle)
    pub allowed_list: Option<Vec<u8>>,     // raw allowed-list
    pub allowed_ekus: Option<Vec<String>>, // EKU OIDs
    pub verify_identity_trust: Option<bool>,
}

impl From<FfiTrustPolicyConfig> for dt::TrustPolicyConfig {
    fn from(v: FfiTrustPolicyConfig) -> Self {
        dt::TrustPolicyConfig { anchors: v.anchors, allowed_list: v.allowed_list, allowed_ekus: v.allowed_ekus, verify_identity_trust: v.verify_identity_trust }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiC2paConfig {
    pub source: FfiAssetRef,
    pub output: FfiOutputTarget,
    pub manifest_definition: Option<String>,
    pub parent: Option<FfiAssetRef>,
    pub parent_base_dir: Option<String>,
    pub signer_uri: String,
    pub signing_alg: FfiSigAlg,
    pub timestamper: Option<FfiTimestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    pub trust_policy: Option<FfiTrustPolicyConfig>,
    pub skip_post_sign_validation: bool,
    pub allow_insecure_remote_http: Option<bool>,
    pub limits: FfiLimitsConfig,
}

impl TryFrom<FfiC2paConfig> for dt::C2paConfig {
    type Error = FfiError;
    fn try_from(v: FfiC2paConfig) -> Result<Self, Self::Error> {
        let signer: Signer = v.signer_uri.parse().map_err(|e| FfiError::Generic { message: format!("Invalid signer: {e}") })?;
        Ok(dt::C2paConfig {
            source: v.source.into(),
            output: v.output.into(),
            manifest_definition: v.manifest_definition,
            parent: v.parent.map(Into::into),
            parent_base_dir: v.parent_base_dir.map(PathBuf::from),
            signer,
            signing_alg: v.signing_alg.into(),
            timestamper: v.timestamper.map(Into::into),
            remote_manifest_url: v.remote_manifest_url,
            embed: v.embed,
            trust_policy: v.trust_policy.map(Into::into),
            skip_post_sign_validation: v.skip_post_sign_validation,
            allow_insecure_remote_http: v.allow_insecure_remote_http,
            limits: v.limits.into(),
            #[cfg(feature = "cawg")]
            cawg_identity: None,
        })
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiC2paVerificationConfig {
    pub source: FfiAssetRef,
    pub mode: FfiVerifyMode,
    pub policy: Option<FfiTrustPolicyConfig>,
    pub allow_remote_manifests: bool,
    pub include_certificates: Option<bool>,
    pub limits: FfiLimitsConfig,
}

impl From<FfiC2paVerificationConfig> for dt::C2paVerificationConfig {
    fn from(v: FfiC2paVerificationConfig) -> Self {
        dt::C2paVerificationConfig {
            source: v.source.into(),
            mode: v.mode.into(),
            policy: v.policy.map(Into::into),
            allow_remote_manifests: v.allow_remote_manifests,
            include_certificates: v.include_certificates,
            limits: v.limits.into(),
            #[cfg(feature = "cawg")]
            cawg: None,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiIngredientConfig {
    pub source: FfiAssetRef,
    pub output: FfiOutputTarget,
    pub limits: FfiLimitsConfig,
}

impl From<FfiIngredientConfig> for dt::IngredientConfig {
    fn from(v: FfiIngredientConfig) -> Self {
        dt::IngredientConfig { source: v.source.into(), output: v.output.into(), limits: v.limits.into() }
    }
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiFragmentedBmffConfig {
    pub init_glob: String,
    pub fragments_glob: String,
    pub output_dir: String,
    pub manifest_definition: Option<String>,
    pub signer_uri: String,
    pub signing_alg: FfiSigAlg,
    pub timestamper: Option<FfiTimestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    pub skip_post_sign_validation: bool,
    pub allow_insecure_remote_http: Option<bool>,
    pub limits: FfiLimitsConfig,
}

impl TryFrom<FfiFragmentedBmffConfig> for dt::FragmentedBmffConfig {
    type Error = FfiError;
    fn try_from(v: FfiFragmentedBmffConfig) -> Result<Self, Self::Error> {
        let signer: Signer = v.signer_uri.parse().map_err(|e| FfiError::Generic { message: format!("Invalid signer: {e}") })?;
        Ok(dt::FragmentedBmffConfig {
            init_glob: PathBuf::from(v.init_glob),
            fragments_glob: PathBuf::from(v.fragments_glob),
            output_dir: PathBuf::from(v.output_dir),
            manifest_definition: v.manifest_definition,
            signer,
            signing_alg: v.signing_alg.into(),
            timestamper: v.timestamper.map(Into::into),
            remote_manifest_url: v.remote_manifest_url,
            embed: v.embed,
            skip_post_sign_validation: v.skip_post_sign_validation,
            allow_insecure_remote_http: v.allow_insecure_remote_http,
            limits: v.limits.into(),
        })
    }
}

// ===== Verification result mappings =====

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiCertInfo {
    pub alg: Option<String>,
    pub issuer: Option<String>,
    pub cert_serial_number: Option<String>,
    pub time: Option<String>,
    pub revocation_status: Option<bool>,
    pub chain_pem: Option<String>,
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiValidationStatus {
    pub code: String,
    pub url: Option<String>,
    pub explanation: Option<String>,
    pub ingredient_uri: Option<String>,
    pub passed: bool,
}

#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum FfiVerdict { Allowed, Warning, Rejected }

#[derive(uniffi::Record, Debug, Clone)]
pub struct FfiVerificationResult {
    pub report: String,
    pub certificates: Option<Vec<FfiCertInfo>>,
    pub status: Option<Vec<FfiValidationStatus>>,
    pub verdict: Option<FfiVerdict>,
    pub is_embedded: Option<bool>,
    pub remote_url: Option<String>,
}

impl From<que_engine::domain::verify::VerificationResult> for FfiVerificationResult {
    fn from(v: que_engine::domain::verify::VerificationResult) -> Self {
        FfiVerificationResult {
            report: v.report,
            certificates: v.certificates.map(|cs| cs.into_iter().map(|c| FfiCertInfo {
                alg: c.alg,
                issuer: c.issuer,
                cert_serial_number: c.cert_serial_number,
                time: c.time,
                revocation_status: c.revocation_status,
                chain_pem: c.chain_pem,
            }).collect()),
            status: v.status.map(|ss| ss.into_iter().map(|s| FfiValidationStatus { code: s.code, url: s.url, explanation: s.explanation, ingredient_uri: s.ingredient_uri, passed: s.passed }).collect()),
            verdict: v.verdict.map(|vd| match vd { que_engine::domain::verify::Verdict::Allowed => FfiVerdict::Allowed, que_engine::domain::verify::Verdict::Warning => FfiVerdict::Warning, que_engine::domain::verify::Verdict::Rejected => FfiVerdict::Rejected }),
            is_embedded: v.is_embedded,
            remote_url: v.remote_url,
        }
    }
}

// ===== High-level API, mirroring Rust surface =====

#[uniffi::export]
pub fn sign_c2pa_ffi(cfg: FfiC2paConfig) -> Result<Option<Vec<u8>>, FfiError> {
    let cfg: dt::C2paConfig = cfg.try_into()?;
    sign_c2pa(cfg).map_err(FfiError::from)
}

#[uniffi::export]
pub fn verify_c2pa_ffi(cfg: FfiC2paVerificationConfig) -> Result<FfiVerificationResult, FfiError> {
    let cfg: dt::C2paVerificationConfig = cfg.into();
    let res = verify_c2pa(cfg).map_err(FfiError::from)?;
    Ok(res.into())
}

#[uniffi::export]
pub fn create_ingredient_ffi(cfg: FfiIngredientConfig) -> Result<Option<Vec<u8>>, FfiError> {
    let cfg: dt::IngredientConfig = cfg.into();
    create_ingredient(cfg).map_err(FfiError::from)
}

#[cfg(all(feature = "c2pa", feature = "bmff"))]
#[uniffi::export]
pub fn generate_fragmented_bmff_ffi(cfg: FfiFragmentedBmffConfig) -> Result<(), FfiError> {
    let cfg: dt::FragmentedBmffConfig = cfg.try_into()?;
    que_engine::generate_fragmented_bmff(cfg).map_err(FfiError::from)
}

// ===== Backward-compatible simple helpers (deprecated) =====

#[uniffi::export]
pub fn sign_file_c2pa(
    signer_spec: String,
    alg: String,
    source_path: String,
    dest_path: String,
    manifest_json: Option<String>,
    parent_path: Option<String>,
    timestamper: Option<String>,
    remote_manifest_url: Option<String>,
    embed: bool,
) -> Result<(), FfiError> {
    let signer: Signer = signer_spec.parse().map_err(|e| FfiError::Generic { message: format!("Invalid signer: {e}") })?;
    let alg = match alg.to_ascii_uppercase().as_str() { "ES256" => dt::SigAlg::Es256, "ES384" => dt::SigAlg::Es384, "PS256" => dt::SigAlg::Ps256, "ED25519" => dt::SigAlg::Ed25519, _ => { return Err(FfiError::Generic { message: format!("Unsupported alg: {alg}") }) } };
    let tsa = match timestamper { None => None, Some(v) if v == "digicert" => Some(Timestamper::Digicert), Some(v) if v.starts_with("custom:") => Some(Timestamper::Custom(v.trim_start_matches("custom:").to_string())), Some(v) => { return Err(FfiError::Generic { message: format!("Invalid timestamper: {v}") }) } };
    let cfg = dt::C2paConfig {
        source: dt::AssetRef::Path(PathBuf::from(source_path)),
        output: dt::OutputTarget::Path(PathBuf::from(dest_path)),
        manifest_definition: manifest_json,
        parent: parent_path.map(|p| dt::AssetRef::Path(PathBuf::from(p))),
        parent_base_dir: None,
        signer,
        signing_alg: alg,
        timestamper: tsa,
        remote_manifest_url,
        embed,
        trust_policy: None,
        skip_post_sign_validation: false,
        allow_insecure_remote_http: None,
        limits: dt::LimitsConfig::defaults(),
        #[cfg(feature = "cawg")]
        cawg_identity: None,
    };
    sign_c2pa(cfg).map(|_| ()).map_err(FfiError::from)
}

#[derive(uniffi::Record)]
pub struct VerifyOptions { pub detailed: bool, pub info: bool, pub tree: bool }

#[uniffi::export]
pub fn verify_file_c2pa(source_path: String, opts: VerifyOptions) -> Result<String, FfiError> {
    let mode = if opts.detailed { dt::VerifyMode::Detailed } else if opts.info { dt::VerifyMode::Info } else if opts.tree { dt::VerifyMode::Tree } else { dt::VerifyMode::Summary };
    let cfg = dt::C2paVerificationConfig { source: dt::AssetRef::Path(PathBuf::from(source_path)), mode, policy: None, allow_remote_manifests: false, include_certificates: None, limits: dt::LimitsConfig::defaults(), #[cfg(feature = "cawg")] cawg: None };
    let report = verify_c2pa(cfg).map_err(FfiError::from)?;
    Ok(report.report)
}

uniffi::setup_scaffolding!();