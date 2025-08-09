use std::path::PathBuf;

use anyhow::Result;
use que_engine::crypto::signer::Signer;
use que_engine::crypto::timestamper::Timestamper;
use que_engine::domain::types::{
    AssetRef, OutputTarget, C2paConfig, C2paVerificationConfig, SigAlg, VerifyMode,
};
use que_engine::{sign_c2pa, verify_c2pa};

pub struct VerifyOptions {
    pub detailed: bool,
    pub info: bool,
    pub tree: bool,
}

#[derive(thiserror::Error, Debug)]
#[error("{message}")]
pub struct FfiError {
    pub message: String,
}

impl From<anyhow::Error> for FfiError {
    fn from(e: anyhow::Error) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}
fn sign_file_c2pa(
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
    let signer: Signer = signer_spec.parse().map_err(|e| FfiError {
        message: format!("Invalid signer: {e}"),
    })?;

    let alg = match alg.to_ascii_uppercase().as_str() {
        "ES256" => SigAlg::Es256,
        "ES384" => SigAlg::Es384,
        "PS256" => SigAlg::Ps256,
        "ED25519" => SigAlg::Ed25519,
        _ => {
            return Err(FfiError {
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
            return Err(FfiError {
                message: format!("Invalid timestamper: {v}"),
            })
        }
    };

    let cfg = C2paConfig {
        source: AssetRef::Path(PathBuf::from(source_path)),
        output: OutputTarget::Path(PathBuf::from(dest_path)),
        manifest_definition: manifest_json,
        parent: parent_path.map(|p| AssetRef::Path(PathBuf::from(p))),
        parent_base_dir: None, // NEW FIELD — set to None for FFI
        signer,
        signing_alg: alg,
        timestamper: tsa,
        remote_manifest_url,
        embed,
        skip_post_sign_validation: false,
    };

    sign_c2pa(cfg).map(|_| ()).map_err(FfiError::from)
}

fn verify_file_c2pa(source_path: String, opts: VerifyOptions) -> Result<String, FfiError> {
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
        source: AssetRef::Path(PathBuf::from(source_path)), // CHANGED: use `source` instead of `source_path`
        mode,
        policy: None,
    };

    let report = verify_c2pa(cfg).map_err(FfiError::from)?;
    Ok(report.report)
}

uniffi::setup_scaffolding!();
