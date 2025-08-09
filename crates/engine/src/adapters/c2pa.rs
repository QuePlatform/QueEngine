// crates/engine/src/adapters/c2pa.rs

//! C2PA-backed ManifestEngine implementation.

#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
    AssetRef, C2paConfig, C2paVerificationConfig, OutputTarget, VerifyMode,
};
use crate::domain::verify::VerificationResult;

pub struct C2pa;

impl ManifestEngine for C2pa {
    type Config = C2paConfig;
    type VerificationConfig = C2paVerificationConfig;
    type Artifact = Option<Vec<u8>>; // Returns bytes if OutputTarget::Memory

    fn generate(config: Self::Config) -> Result<Self::Artifact> {
        #[cfg(not(feature = "c2pa"))]
        {
            anyhow::bail!("C2PA feature not enabled");
        }

        #[cfg(feature = "c2pa")]
        {
            // ... (code for preparing manifest_json is unchanged) ...
            let manifest_json = match config.manifest_definition {
                Some(json_str) => {
                    if let Some(tsa) = &config.timestamper {
                        let mut manifest_val: Value = serde_json::from_str(
                            &json_str,
                        )
                        .context("Failed to parse user-provided manifest")?;
                        if let Some(obj) = manifest_val.as_object_mut() {
                            if let Some(url) = tsa.resolve() {
                                obj.insert(
                                    "ta_url".to_string(),
                                    Value::String(url),
                                );
                            }
                        }
                        serde_json::to_string(&manifest_val)?
                    } else {
                        json_str
                    }
                }
                None => {
                    let mut manifest_val = serde_json::json!({});
                    if let Some(tsa) = &config.timestamper {
                        if let Some(url) = tsa.resolve() {
                            manifest_val["ta_url"] = Value::String(url);
                        }
                    }
                    serde_json::to_string(&manifest_val)?
                }
            };

            let mut builder = c2pa::Builder::from_json(&manifest_json)
                .context("Failed to create builder from manifest")?;

            if let Some(parent_path) = &config.parent_path {
                let parent_ingredient = Ingredient::from_file(parent_path)
                    .context("Failed to create ingredient from parent file")?;
                builder.add_ingredient(parent_ingredient);
            }

            let alg = config.signing_alg.to_c2pa();
            let signer = config.signer.resolve(alg)?;

            if let Some(remote_url) = config.remote_manifest_url {
                builder.set_remote_url(remote_url);
            }
            if !config.embed {
                builder.set_no_embed(true);
            }

            // Handle AssetRef + OutputTarget.
            let (src_path, _tmp_src_dir) = match &config.source {
                AssetRef::Path(p) => (p.clone(), None),
                AssetRef::Bytes(bytes) => {
                    let dir = tempfile::tempdir()
                        .context("Failed to create temp dir for source asset")?;
                    let p = dir.path().join("source_asset");
                    std::fs::write(&p, bytes)
                        .context("Failed to write source asset to temp file")?;
                    (p, Some(dir))
                }
            };

            match &config.output {
                OutputTarget::Path(dest) => {
                    builder
                        .sign_file(&*signer, &src_path, dest)
                        .context("Failed to sign and embed C2PA manifest")?;
                    Ok(None)
                }
                OutputTarget::Memory => {
                    let dir = tempfile::tempdir()
                        .context("Failed to create temp dir for output")?;
                    let out_path = dir.path().join("output_asset");
                    builder
                        .sign_file(&*signer, &src_path, &out_path)
                        .context("Failed to sign and embed C2PA manifest")?;
                    let buf = std::fs::read(&out_path)
                        .context("Failed to read signed asset from temp file")?;
                    Ok(Some(buf))
                }
            }
        }
    }

    fn verify(config: Self::VerificationConfig) -> Result<VerificationResult> {
        // ... (verify implementation is unchanged and correct) ...
        #[cfg(not(feature = "c2pa"))]
        {
            anyhow::bail!("C2PA feature not enabled");
        }

        #[cfg(feature = "c2pa")]
        {
            let reader = Reader::from_file(&config.source_path)
                .context("Failed to read C2PA data from file")?;

            let report_str = match config.mode {
                VerifyMode::Detailed => format!("{:?}", reader),
                VerifyMode::Info => format!("{}", reader),
                VerifyMode::Tree => format!("{:?}", reader),
                VerifyMode::Summary => format!("{}", reader),
            };

            Ok(VerificationResult {
                report: report_str,
            })
        }
    }
}