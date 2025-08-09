//! C2PA-backed ManifestEngine implementation.

#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};

use anyhow::{Context, Result};
use serde_json::Value;

// Note: Removed unused imports for Signer and Timestamper
use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
    C2paConfig, C2paVerificationConfig, SigAlg, VerifyMode,
};
use crate::domain::verify::VerificationResult;

pub struct C2pa;

impl ManifestEngine for C2pa {
    type Config = C2paConfig;
    type VerificationConfig = C2paVerificationConfig;
    type Artifact = ();

    fn generate(config: Self::Config) -> Result<Self::Artifact> {
        #[cfg(not(feature = "c2pa"))]
        {
            anyhow::bail!("C2PA feature not enabled");
        }

        #[cfg(feature = "c2pa")]
        {
            // 1) Prepare manifest JSON and inject TSA URL if present.
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

            // 2) Build from JSON.
            let mut builder = c2pa::Builder::from_json(&manifest_json)
                .context("Failed to create builder from manifest")?;

            // 3) Optional parent ingredient.
            if let Some(parent_path) = &config.parent_path {
                let parent_ingredient = Ingredient::from_file(parent_path)
                    .context("Failed to create ingredient from parent file")?;
                builder.add_ingredient(parent_ingredient);
            }

            // 4) Resolve signer and algorithm.
            let alg = match config.signing_alg {
                SigAlg::Es256 => c2pa::SigningAlg::Es256,
                SigAlg::Es384 => c2pa::SigningAlg::Es384,
                SigAlg::Ps256 => c2pa::SigningAlg::Ps256,
                SigAlg::Ed25519 => c2pa::SigningAlg::Ed25519,
            };
            let signer = config.signer.resolve(alg)?;

            // 5) Remote manifest and embedding options.
            if let Some(remote_url) = config.remote_manifest_url {
                builder.set_remote_url(remote_url);
            }
            if !config.embed {
                builder.set_no_embed(true);
            }

            // 6) Sign and write.
            builder
                .sign_file(&*signer, &config.source_path, &config.dest_path)
                .context("Failed to sign and embed C2PA manifest")?;
            Ok(())
        }
    }

    fn verify(config: Self::VerificationConfig) -> Result<VerificationResult> {
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