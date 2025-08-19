// crates/engine/src/adapters/c2pa.rs
#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};

use once_cell::sync::Lazy;
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use crate::crypto::timestamper::Timestamper;
use crate::domain::error::{EngineError, EngineResult};
use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
  AssetRef, C2paConfig, C2paVerificationConfig, OutputTarget, VerifyMode,
};
use crate::domain::verify::{CertInfo, ValidationStatus, VerificationResult, Verdict};

static C2PA_SETTINGS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static BASE_SETTINGS: &str = r#"{}"#;

fn apply_settings(jsons: &[serde_json::Value]) -> EngineResult<()> {
  #[cfg(not(feature = "c2pa"))]
  {
    return Err(EngineError::Feature("c2pa"));
  }
  #[cfg(feature = "c2pa")]
  {
    c2pa::settings::load_settings_from_str(BASE_SETTINGS, "json")?;
    for s in jsons {
      c2pa::settings::load_settings_from_str(&s.to_string(), "json")?;
    }
    Ok(())
  }
}

fn with_c2pa_settings<F, T>(settings: &[serde_json::Value], f: F) -> EngineResult<T>
where
  F: FnOnce() -> EngineResult<T>,
{
  let _guard = C2PA_SETTINGS_LOCK
    .lock()
    .map_err(|_| EngineError::Panic("settings mutex poisoned".into()))?;

  apply_settings(settings)?;

  let result = catch_unwind(AssertUnwindSafe(|| f()));

  // Always attempt to restore baseline settings
  #[cfg(feature = "c2pa")]
  let _ = c2pa::settings::load_settings_from_str(BASE_SETTINGS, "json");

  match result {
    Ok(r) => r,
    Err(_) => Err(EngineError::Panic("c2pa adapter panicked".into())),
  }
}

fn prepare_manifest_json(
  manifest_definition: Option<String>,
  timestamper: &Option<Timestamper>,
) -> EngineResult<String> {
  match manifest_definition {
    Some(json_str) => {
      if let Some(tsa) = timestamper {
        let mut manifest_val: Value = serde_json::from_str(&json_str)?;
        if let Some(obj) = manifest_val.as_object_mut() {
          if let Some(url) = tsa.resolve() {
            obj.insert("ta_url".to_string(), Value::String(url));
          }
        }
        Ok(serde_json::to_string(&manifest_val)?)
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
      Ok(serde_json::to_string(&manifest_val)?)
    }
  }
}

fn asset_to_temp_path(
  asset: &AssetRef,
) -> EngineResult<(std::path::PathBuf, Option<tempfile::TempDir>)> {
  match asset {
    AssetRef::Path(p) => Ok((p.clone(), None)),
    AssetRef::Bytes { data, ext } => {
      let dir = tempfile::tempdir()?;
      let filename = ext
        .as_deref()
        .map(|e| format!("asset.{e}"))
        .unwrap_or_else(|| {
          // Infer extension from file content when none provided
          if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
            "asset.jpg".to_string()
          } else if data.len() >= 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
            "asset.png".to_string()
          } else if data.len() >= 4 && data[..4] == [0x52, 0x49, 0x46, 0x46] && data.len() >= 12 && data[8..12] == [0x57, 0x45, 0x42, 0x50] {
            "asset.webp".to_string()
          } else if data.len() >= 4 && data[..4] == [0x00, 0x00, 0x00, 0x18] && data.len() >= 8 && data[4..8] == [0x66, 0x74, 0x79, 0x70] {
            "asset.mp4".to_string()
          } else {
            "asset".to_string() // fallback to no extension
          }
        });
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

  fn generate(config: Self::Config) -> EngineResult<Self::Artifact> {
    #[cfg(not(feature = "c2pa"))]
    {
      return Err(EngineError::Feature("c2pa"));
    }
    #[cfg(feature = "c2pa")]
    {
      let mut settings = vec![serde_json::json!({
        "verify": { "verify_after_sign": !config.skip_post_sign_validation }
      })];

      // If trust policy is provided, mirror the same trust settings used by verify().
      if let Some(policy) = &config.trust_policy {
        let mut enable_trust = false;
        if let Some(anchors) = &policy.anchors {
          let pem = String::from_utf8_lossy(anchors);
          settings.push(serde_json::json!({
            "trust": { "trust_anchors": pem, "trust_anchors_path": null }
          }));
          enable_trust = true;
        }
        if let Some(allowed) = &policy.allowed_list {
          let pem = String::from_utf8_lossy(allowed);
          settings.push(serde_json::json!({
            "trust": { "allowed_list": pem, "allowed_list_path": null }
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
             // Preserve the source file extension for the output so the c2pa
            // library can determine the correct handler (e.g., jpeg, png, etc.).
            let out_filename = match src_path.extension().and_then(|e| e.to_str()) {
              Some(ext_str) if !ext_str.is_empty() => format!("output_asset.{ext_str}"),
              _ => "output_asset".to_string(),
            };
            let out_path = dir.path().join(out_filename);
            builder.sign_file(&*signer, &src_path, &out_path)?;
            let buf = std::fs::read(&out_path)?;
            Ok(Some(buf))
          }
        }
      })
    }
  }

  fn verify(config: Self::VerificationConfig) -> EngineResult<VerificationResult> {
    #[cfg(not(feature = "c2pa"))]
    {
      return Err(EngineError::Feature("c2pa"));
    }
    #[cfg(feature = "c2pa")]
    {
      let mut settings = Vec::new();
      settings.push(serde_json::json!({
        "verify": { "fetch_remote_manifests": config.allow_remote_manifests }
      }));

      if let Some(policy) = &config.policy {
        let mut enable_trust = false;
        if let Some(anchors) = &policy.anchors {
          let pem = String::from_utf8_lossy(anchors);
          settings.push(serde_json::json!({
            "trust": { "trust_anchors": pem, "trust_anchors_path": null }
          }));
          enable_trust = true;
        }
        if let Some(allowed) = &policy.allowed_list {
          let pem = String::from_utf8_lossy(allowed);
          settings.push(serde_json::json!({
            "trust": { "allowed_list": pem, "allowed_list_path": null }
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

        let status_vec = reader.validation_status().map(|arr| {
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

        let verdict = status_vec.as_ref().map(|statuses| {
          if statuses.iter().any(|s| !s.passed) {
            Verdict::Rejected
          } else if statuses.iter().any(|s| s.code.contains("warning")) {
            Verdict::Warning
          } else {
            Verdict::Allowed
          }
        });

        Ok(VerificationResult {
          report: report_str,
          certificates,
          status: status_vec,
          verdict,
        })
      })
    }
  }
}

impl C2pa {
  #[cfg(all(feature = "c2pa", feature = "bmff"))]
  pub fn generate_fragmented_bmff(
    cfg: crate::domain::types::FragmentedBmffConfig,
  ) -> EngineResult<()> {
    let settings = vec![serde_json::json!({
      "verify": { "verify_after_sign": !cfg.skip_post_sign_validation }
    })];

    with_c2pa_settings(&settings, || {
      let manifest_json =
        prepare_manifest_json(cfg.manifest_definition, &cfg.timestamper)?;
      let mut builder = c2pa::Builder::from_json(&manifest_json)?;
      let alg = cfg.signing_alg.to_c2pa();
      let signer = cfg.signer.resolve(alg)?;

      if let Some(remote_url) = cfg.remote_manifest_url {
        builder.set_remote_url(remote_url);
      }
      if !cfg.embed {
        builder.set_no_embed(true);
      }

      std::fs::create_dir_all(&cfg.output_dir)?;

      let init_glob_str = cfg
        .init_glob
        .to_str()
        .ok_or_else(|| EngineError::Config("init_glob is not valid UTF-8".into()))?;

      for init_entry in glob::glob(init_glob_str)? {
        let init_path = init_entry?;
        let init_dir = init_path
          .parent()
          .ok_or_else(|| EngineError::Config("init segment has no parent".into()))?;

        let frag_glob_path = init_dir.join(&cfg.fragments_glob);
        let frag_glob_str = frag_glob_path.to_str().ok_or_else(|| {
          EngineError::Config("fragments_glob is not valid UTF-8".into())
        })?;

        let mut fragments = Vec::new();
        for frag_entry in glob::glob(frag_glob_str)? {
          fragments.push(frag_entry?);
        }

        let sub_output_dir = cfg.output_dir.join(
          init_dir
            .file_name()
            .ok_or_else(|| EngineError::Config("invalid init dir name".into()))?,
        );
        std::fs::create_dir_all(&sub_output_dir)?;

        builder.sign_fragmented_files(&*signer, &init_path, &fragments, &sub_output_dir)?;
      }

      Ok(())
    })
  }

  #[cfg(feature = "c2pa")]
  pub fn create_ingredient(
    config: crate::domain::types::IngredientConfig,
  ) -> EngineResult<Option<Vec<u8>>> {
    let (source_path, _temp_dir) = asset_to_temp_path(&config.source)?;
    match config.output {
      OutputTarget::Path(dir) => {
        std::fs::create_dir_all(&dir)?;
        let report = Ingredient::from_file_with_folder(&source_path, &dir)?;
        std::fs::write(dir.join("ingredient.json"), report.to_string())?;
        Ok(None)
      }
      OutputTarget::Memory => {
        let report = Ingredient::from_file(&source_path)?.to_string();
        Ok(Some(report.into_bytes()))
      }
    }
  }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::EngineError;

    #[test]
    fn with_c2pa_settings_catches_panics() {
        let res = super::with_c2pa_settings(&[], || -> EngineResult<()> {
            panic!("boom");
        });
        assert!(matches!(res, Err(EngineError::Panic(_))));
    }
}