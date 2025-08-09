// crates/engine/src/adapters/c2pa.rs

//! C2PA-backed ManifestEngine implementation.

#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::sync::Mutex;

use crate::crypto::timestamper::Timestamper;
use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
    AssetRef, C2paConfig, C2paVerificationConfig, FragmentedBmffConfig,
    IngredientConfig, OutputTarget, VerifyMode,
};
use crate::domain::verify::{
    CertInfo, ValidationStatus, VerificationResult,
};

static C2PA_SETTINGS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn with_c2pa_settings<F, T>(
    settings: &[serde_json::Value],
    f: F,
) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let _guard = C2PA_SETTINGS_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("C2PA settings mutex was poisoned"))?;
    for s in settings {
        c2pa::settings::load_settings_from_str(&s.to_string(), "json")
            .context("Failed to load C2PA settings")?;
    }
    f()
}

fn prepare_manifest_json(
    manifest_definition: Option<String>,
    timestamper: &Option<Timestamper>,
) -> Result<String> {
    match manifest_definition {
        Some(json_str) => {
            if let Some(tsa) = timestamper {
                let mut manifest_val: Value = serde_json::from_str(&json_str)
                    .context("Failed to parse user-provided manifest")?;
                if let Some(obj) = manifest_val.as_object_mut() {
                    if let Some(url) = tsa.resolve() {
                        obj.insert("ta_url".to_string(), Value::String(url));
                    }
                }
                serde_json::to_string(&manifest_val)
                    .context("Failed to re-serialize manifest JSON")
            } else {
                Ok(json_str)
            }
        }
        None => {
            let mut manifest_val = serde_json::json!({});
            if let Some(tsa) = timestamper {
                if let Some(url) = tsa.resolve() {
                    manifest_val["ta_url"] = Value::String(url);
                }
            }
            serde_json::to_string(&manifest_val)
                .context("Failed to serialize empty manifest JSON")
        }
    }
}

fn asset_to_temp_path(
    asset: &AssetRef,
) -> Result<(std::path::PathBuf, Option<tempfile::TempDir>)> {
    match asset {
        AssetRef::Path(p) => Ok((p.clone(), None)),
        AssetRef::Bytes { data, ext } => {
            let dir = tempfile::tempdir()?;
            let filename = match ext {
                Some(e) => format!("asset.{}", e),
                None => "asset".to_string(),
            };
            let path = dir.path().join(filename);
            std::fs::write(&path, data)?;
            Ok((path, Some(dir)))
        }
    }
}

pub struct C2pa;

impl ManifestEngine for C2pa {
    type Config = C2paConfig;
    type VerificationConfig = C2paVerificationConfig;
    type Artifact = Option<Vec<u8>>;

    fn generate(config: Self::Config) -> Result<Self::Artifact> {
        #[cfg(not(feature = "c2pa"))]
        {
            anyhow::bail!("C2PA feature not enabled");
        }

        #[cfg(feature = "c2pa")]
        {
            let settings = vec![serde_json::json!({
                "verify": { "verify_after_sign": !config.skip_post_sign_validation }
            })];

            with_c2pa_settings(&settings, || {
                let manifest_json = prepare_manifest_json(
                    config.manifest_definition,
                    &config.timestamper,
                )?;

                let mut builder = c2pa::Builder::from_json(&manifest_json)?;

                if let Some(parent) = &config.parent {
                    let mut parent_ingredient = match parent {
                        AssetRef::Path(p) => Ingredient::from_file(p)?,
                        AssetRef::Bytes { data, .. } => {
                            let mut ing: Ingredient = serde_json::from_slice(data)?;
                            if let Some(base) = &config.parent_base_dir {
                                ing.resources_mut().set_base_path(base.clone());
                            }
                            ing
                        }
                    };
                    parent_ingredient.set_is_parent();
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

                let (src_path, _tmp_src_dir) = asset_to_temp_path(&config.source)?;

                match &config.output {
                    OutputTarget::Path(dest) => {
                        builder.sign_file(&*signer, &src_path, dest)?;
                        Ok(None)
                    }
                    OutputTarget::Memory => {
                        let dir = tempfile::tempdir()?;
                        let out_path = dir.path().join("output_asset");
                        builder.sign_file(&*signer, &src_path, &out_path)?;
                        let buf = std::fs::read(&out_path)?;
                        Ok(Some(buf))
                    }
                }
            })
        }
    }

    fn verify(config: Self::VerificationConfig) -> Result<VerificationResult> {
        #[cfg(not(feature = "c2pa"))]
        {
            anyhow::bail!("C2PA feature not enabled");
        }

        #[cfg(feature = "c2pa")]
        {
            let mut settings = Vec::new();
            if let Some(policy) = &config.policy {
                let mut enable_trust = false;
                if let Some(anchors) = &policy.anchors {
                    settings.push(serde_json::json!({
                        "trust": { "trust_anchors": String::from_utf8_lossy(anchors) }
                    }));
                    enable_trust = true;
                }
                if let Some(allowed) = &policy.allowed_list {
                    settings.push(serde_json::json!({
                        "trust": { "allowed_list": String::from_utf8_lossy(allowed) }
                    }));
                    enable_trust = true;
                }
                if let Some(ekus) = &policy.allowed_ekus {
                    settings.push(serde_json::json!({
                        "trust": { "trust_config": { "ekus": ekus } }
                    }));
                    enable_trust = true;
                }
                settings.push(serde_json::json!({
                    "verify": { "verify_trust": enable_trust }
                }));
            }

            with_c2pa_settings(&settings, || {
                let (src_path, _tmp_dir) = asset_to_temp_path(&config.source)?;
                let reader = Reader::from_file(&src_path)?;

                let report_str = match config.mode {
                    VerifyMode::Detailed => format!("{:?}", reader),
                    VerifyMode::Info => format!("{}", reader),
                    VerifyMode::Tree => format!("{:?}", reader),
                    VerifyMode::Summary => format!("{}", reader),
                };

                let certificates = reader
                    .active_manifest()
                    .and_then(|m| m.signature_info())
                    .map(|ci| {
                        vec![CertInfo {
                            alg: ci.alg.map(|a| a.to_string()),
                            issuer: ci.issuer.clone(),
                            cert_serial_number: ci.cert_serial_number.clone(),
                            time: ci.time.clone(),
                            revocation_status: ci.revocation_status,
                            chain_pem: if ci.cert_chain.is_empty() {
                                None
                            } else {
                                Some(ci.cert_chain.clone())
                            },
                        }]
                    });

                let status = reader.validation_status().map(|arr| {
                    arr.iter()
                        .map(|s| ValidationStatus {
                            code: s.code().to_string(),
                            url: s.url().map(|u| u.to_string()),
                            explanation: s.explanation().map(|e| e.to_string()),
                            ingredient_uri: s.ingredient_uri().map(|i| i.to_string()),
                            passed: s.passed(),
                        })
                        .collect()
                });

                Ok(VerificationResult { report: report_str, certificates, status })
            })
        }
    }
}

impl C2pa {
    #[cfg(feature = "c2pa")]
    pub fn create_ingredient(config: IngredientConfig) -> Result<Option<Vec<u8>>> {
        let (source_path, _temp_dir) = asset_to_temp_path(&config.source)?;

        match config.output {
            OutputTarget::Path(dir) => {
                std::fs::create_dir_all(&dir)?;
                let report = Ingredient::from_file_with_folder(&source_path, &dir)?;
                std::fs::write(dir.join("ingredient.json"), report.to_string().as_bytes())?;
                Ok(None)
            }
            OutputTarget::Memory => {
                let report = Ingredient::from_file(&source_path)?.to_string();
                Ok(Some(report.into_bytes()))
            }
        }
    }

    #[cfg(feature = "c2pa")]
    pub fn generate_fragmented_bmff(cfg: FragmentedBmffConfig) -> Result<()> {
        let settings = vec![serde_json::json!({
            "verify": { "verify_after_sign": !cfg.skip_post_sign_validation }
        })];

        with_c2pa_settings(&settings, || {
            let manifest_json = prepare_manifest_json(cfg.manifest_definition, &cfg.timestamper)?;
            let mut builder = c2pa::Builder::from_json(&manifest_json)?;
            let alg = cfg.signing_alg.to_c2pa();
            let signer = cfg.signer.resolve(alg)?;

            if let Some(remote_url) = cfg.remote_manifest_url {
                builder.set_remote_url(remote_url);
            }
            if !cfg.embed {
                builder.set_no_embed(true);
            }

            let ip = cfg.init_glob.to_str().context("Init glob pattern is not valid UTF-8")?;
            for init_entry in glob::glob(ip)? {
                let p = init_entry?;
                let mut fragments = Vec::new();
                let init_dir = p.parent().context("Init segment has no parent directory")?;
                let seg_glob = init_dir.join(&cfg.fragments_glob);
                let seg_glob_str = seg_glob.to_str().context("Fragment glob pattern is not valid UTF-8")?;
                for seg_entry in glob::glob(seg_glob_str)? {
                    fragments.push(seg_entry?);
                }
                let new_output_path = cfg.output_dir.join(init_dir.file_name().context("Invalid file name")?);
                builder.sign_fragmented_files(&*signer, &p, &fragments, &new_output_path)?;
            }
            Ok(())
        })
    }
}