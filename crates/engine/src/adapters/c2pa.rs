// crates/engine/src/adapters/c2pa.rs

//! C2PA-backed ManifestEngine implementation.

#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
    AssetRef, C2paConfig, C2paVerificationConfig, FragmentedBmffConfig, IngredientConfig,
    OutputTarget, TrustPolicyConfig, VerifyMode,
};
use crate::domain::verify::{CertInfo, ValidationStatus, VerificationResult};

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

            if let Some(parent) = &config.parent {
                let mut parent_ingredient = match parent {
                    AssetRef::Path(p) => Ingredient::from_file(p)
                        .context("Failed to create ingredient from parent file")?,
                    AssetRef::Bytes(b) => {
                        // Interpret bytes as ingredient.json
                        let mut ing: Ingredient = serde_json::from_slice(b)
                            .context("Failed to parse parent ingredient bytes as JSON")?;
                        if let Some(base) = std::env::current_dir().ok() {
                            ing.resources_mut().set_base_path(base);
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

            // Configure post-sign verify behavior in SDK settings
            #[cfg(feature = "c2pa")]
            {
                let vs = serde_json::json!({
                    "verify": { "verify_after_sign": !config.skip_post_sign_validation }
                });
                c2pa::settings::load_settings_from_str(&vs.to_string(), "json")
                    .context("Failed to configure c2pa verify_after_sign setting")?;
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
        #[cfg(not(feature = "c2pa"))]
        {
            anyhow::bail!("C2PA feature not enabled");
        }

        #[cfg(feature = "c2pa")]
        {
            // Apply trust policy settings if provided
            if let Some(policy) = &config.policy {
                let mut enable_trust = false;
                if let Some(anchors) = &policy.anchors {
                    let setting = serde_json::json!({
                        "trust": { "trust_anchors": String::from_utf8_lossy(anchors) }
                    });
                    c2pa::settings::load_settings_from_str(&setting.to_string(), "json")?;
                    enable_trust = true;
                }
                if let Some(allowed) = &policy.allowed_list {
                    let setting = serde_json::json!({
                        "trust": { "allowed_list": String::from_utf8_lossy(allowed) }
                    });
                    c2pa::settings::load_settings_from_str(&setting.to_string(), "json")?;
                    enable_trust = true;
                }
                if let Some(ekus) = &policy.allowed_ekus {
                    let setting = serde_json::json!({
                        "trust": { "trust_config": serde_json::json!({"ekus": ekus}) }
                    });
                    c2pa::settings::load_settings_from_str(&setting.to_string(), "json")?;
                    enable_trust = true;
                }
                let verify_setting = serde_json::json!({
                    "verify": { "verify_trust": enable_trust }
                });
                c2pa::settings::load_settings_from_str(&verify_setting.to_string(), "json")?;
            }

            let reader = Reader::from_file(&config.source_path)
                .context("Failed to read C2PA data from file")?;

            let report_str = match config.mode {
                VerifyMode::Detailed => format!("{:?}", reader),
                VerifyMode::Info => format!("{}", reader),
                VerifyMode::Tree => format!("{:?}", reader),
                VerifyMode::Summary => format!("{}", reader),
            };

            // Extract cert info if available
            let certificates = reader
                .active_manifest()
                .and_then(|m| m.signature_info())
                .map(|ci| {
                    let mut list = Vec::new();
                    let info = CertInfo {
                        alg: ci.alg.map(|a| a.to_string()),
                        issuer: ci.issuer.clone(),
                        cert_serial_number: ci.cert_serial_number.clone(),
                        time: ci.time.clone(),
                        revocation_status: ci.revocation_status,
                        cert_chain: if ci.cert_chain.is_empty() {
                            None
                        } else {
                            Some(ci.cert_chain.clone().into_bytes())
                        },
                    };
                    list.push(info);
                    list
                });

            // Map validation status entries
            let status = reader.validation_status().map(|arr| {
                arr.iter()
                    .map(|s| ValidationStatus {
                        code: s.code().to_string(),
                        url: s.url().map(|u| u.to_string()),
                        explanation: s.explanation().map(|e| e.to_string()),
                        ingredient_uri: s.ingredient_uri().map(|i| i.to_string()),
                        passed: s.passed(),
                    })
                    .collect::<Vec<_>>()
            });

            Ok(VerificationResult { report: report_str, certificates, status })
        }
    }
}

impl C2pa {
    /// Create a standalone ingredient from an asset, returning bytes or writing folder.
    #[cfg(feature = "c2pa")]
    pub fn create_ingredient(config: IngredientConfig) -> Result<Option<Vec<u8>>> {
        match (config.source, config.output) {
            (AssetRef::Path(p), OutputTarget::Path(dir)) => {
                std::fs::create_dir_all(&dir)?;
                let report = Ingredient::from_file_with_folder(&p, &dir)?;
                std::fs::write(dir.join("ingredient.json"), report.to_string().as_bytes())?;
                Ok(None)
            }
            (AssetRef::Path(p), OutputTarget::Memory) => {
                let report = Ingredient::from_file(&p)?.to_string();
                Ok(Some(report.into_bytes()))
            }
            (AssetRef::Bytes(b), OutputTarget::Memory) => {
                // Write temp file from bytes and then build ingredient
                let dir = tempfile::tempdir()?;
                let src = dir.path().join("source_asset");
                std::fs::write(&src, &b)?;
                let report = Ingredient::from_file(&src)?.to_string();
                Ok(Some(report.into_bytes()))
            }
            (AssetRef::Bytes(b), OutputTarget::Path(dir)) => {
                let tdir = tempfile::tempdir()?;
                let src = tdir.path().join("source_asset");
                std::fs::write(&src, &b)?;
                std::fs::create_dir_all(&dir)?;
                let report = Ingredient::from_file_with_folder(&src, &dir)?;
                std::fs::write(dir.join("ingredient.json"), report.to_string().as_bytes())?;
                Ok(None)
            }
        }
    }

    /// Sign fragmented BMFF content (init + fragments) into an output directory.
    #[cfg(feature = "c2pa")]
    pub fn generate_fragmented_bmff(cfg: FragmentedBmffConfig) -> Result<()> {
        let manifest_json = match cfg.manifest_definition {
            Some(json_str) => {
                if let Some(tsa) = &cfg.timestamper {
                    let mut manifest_val: Value = serde_json::from_str(&json_str)
                        .context("Failed to parse user-provided manifest")?;
                    if let Some(obj) = manifest_val.as_object_mut() {
                        if let Some(url) = tsa.resolve() {
                            obj.insert("ta_url".to_string(), Value::String(url));
                        }
                    }
                    serde_json::to_string(&manifest_val)?
                } else {
                    json_str
                }
            }
            None => serde_json::to_string(&serde_json::json!({}))?,
        };

        let mut builder = c2pa::Builder::from_json(&manifest_json)
            .context("Failed to create builder from manifest")?;

        let alg = cfg.signing_alg.to_c2pa();
        let signer = cfg.signer.resolve(alg)?;
        if let Some(remote_url) = cfg.remote_manifest_url {
            builder.set_remote_url(remote_url);
        }
        if !cfg.embed {
            builder.set_no_embed(true);
        }
        // Configure SDK verify-after-sign
        let vs = serde_json::json!({
            "verify": { "verify_after_sign": !cfg.skip_post_sign_validation }
        });
        c2pa::settings::load_settings_from_str(&vs.to_string(), "json")
            .context("Failed to configure c2pa verify_after_sign setting")?;

        let ip = cfg
            .init_glob
            .to_str()
            .ok_or(c2pa::Error::OtherError("could not parse source pattern".into()))?;
        let inits = glob::glob(ip).context("could not process glob pattern")?;
        for init in inits {
            let p = init.context("bad path to init segment")?;
            let mut fragments = Vec::new();
            let init_dir = p.parent().context("init segment had no parent dir")?;
            let seg_glob = init_dir.join(&cfg.fragments_glob);
            let seg_glob_str = seg_glob
                .to_str()
                .context("fragment path not valid")?;
            let seg_paths = glob::glob(seg_glob_str).context("fragment glob not valid")?;
            for seg in seg_paths {
                fragments.push(seg.context("fragment path not valid")?);
            }
            let new_output_path = cfg
                .output_dir
                .join(init_dir.file_name().context("invalid file name")?);
            builder.sign_fragmented_files(&*signer, &p, &fragments, &new_output_path)?;
        }
        Ok(())
    }
}