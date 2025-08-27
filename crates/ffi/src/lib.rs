use std::path::PathBuf;

use que_engine::crypto::signer::Signer;
use que_engine::crypto::timestamper::Timestamper;
use que_engine::domain::types::{
    AssetRef, OutputTarget, C2paConfig, C2paVerificationConfig, SigAlg, VerifyMode,
};
use que_engine::domain::error::EngineError;
use que_engine::{sign_c2pa, verify_c2pa};

#[derive(uniffi::Record)]
pub struct VerifyOptions {
    pub detailed: bool,
    pub info: bool,
    pub tree: bool,
}

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
    let signer: Signer = signer_spec.parse().map_err(|e| FfiError::Generic {
        message: format!("Invalid signer: {e}"),
    })?;

    let alg = match alg.to_ascii_uppercase().as_str() {
        "ES256" => SigAlg::Es256,
        "ES384" => SigAlg::Es384,
        "PS256" => SigAlg::Ps256,
        "ED25519" => SigAlg::Ed25519,
        _ => {
            return Err(FfiError::Generic {
                message: format!("Unsupported alg: {alg}"),
            })
        }
    };

    let tsa = match timestamper {
        None => None,
        Some(v) if v == "digicert" => Some(Timestamper::Digicert),
        Some(v) if v.starts_with("custom:") => {
            Some(Timestamper::Custom(v.trim_start_matches("custom:").to_string()))
        }
        Some(v) => {
            return Err(FfiError::Generic {
                message: format!("Invalid timestamper: {v}"),
            })
        }
    };

    let cfg = C2paConfig {
        source: AssetRef::Path(PathBuf::from(source_path)),
        output: OutputTarget::Path(PathBuf::from(dest_path)),
        manifest_definition: manifest_json,
        parent: parent_path.map(|p| AssetRef::Path(PathBuf::from(p))),
        parent_base_dir: None,
        signer,
        signing_alg: alg,
        timestamper: tsa,
        remote_manifest_url,
        embed,
        trust_policy: None,
        skip_post_sign_validation: false,
        allow_insecure_remote_http: None,
    };

    sign_c2pa(cfg).map(|_| ()).map_err(FfiError::from)
}

#[uniffi::export]
pub fn verify_file_c2pa(source_path: String, opts: VerifyOptions) -> Result<String, FfiError> {
    let mode = if opts.detailed {
        VerifyMode::Detailed
    } else if opts.info {
        VerifyMode::Info
    } else if opts.tree {
        VerifyMode::Tree
    } else {
        VerifyMode::Summary
    };

    let cfg = C2paVerificationConfig {
        source: AssetRef::Path(PathBuf::from(source_path)),
        mode,
        policy: None,
        allow_remote_manifests: false,
        include_certificates: None,
    };

    let report = verify_c2pa(cfg).map_err(FfiError::from)?;
    Ok(report.report)
}

uniffi::setup_scaffolding!();