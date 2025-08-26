#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};
use crate::domain::error::{EngineError, EngineResult};
use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
  AssetRef, C2paConfig, C2paVerificationConfig, OutputTarget, VerifyMode,
};
use crate::domain::verify::{CertInfo, ValidationStatus, VerificationResult, Verdict};

use super::constants::MAX_IN_MEMORY_OUTPUT_SIZE;
use super::asset_utils::asset_to_temp_path;
use super::settings::{with_c2pa_settings, prepare_manifest_json};
use super::url_validation::validate_external_http_url;

pub struct C2pa;

impl C2pa {
  fn build_trust_settings(policy: &crate::domain::types::TrustPolicy) -> EngineResult<(Vec<serde_json::Value>, bool)> {
    let mut settings = Vec::new();
    let mut enable_trust = false;

    if let Some(anchors) = &policy.anchors {
      let pem = std::str::from_utf8(anchors)
        .map_err(|_| EngineError::Config("trust anchors must be valid UTF-8".into()))?
        .to_owned();
      settings.push(serde_json::json!({
        "trust": { "trust_anchors": pem, "trust_anchors_path": null }
      }));
      enable_trust = true;
    }

    if let Some(allowed) = &policy.allowed_list {
      let pem = std::str::from_utf8(allowed)
        .map_err(|_| EngineError::Config("allowed list must be valid UTF-8".into()))?
        .to_owned();
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

    if let Some(v) = policy.verify_identity_trust {
      settings.push(serde_json::json!({
        "verify": { "verify_identity_trust": v }
      }));
    }

    Ok((settings, enable_trust))
  }
}

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
        let (trust_settings, enable_trust) = Self::build_trust_settings(policy)?;
        settings.extend(trust_settings);
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
            AssetRef::Bytes { data } => {
              let mut ing: Ingredient = serde_json::from_slice(data)?;
              if let Some(base) = &config.parent_base_dir {
                ing.resources_mut().set_base_path(base.clone());
              }
              ing
            }
            AssetRef::Stream { .. } => {
              return Err(EngineError::Config("parent ingredients from streams are not currently supported".into()));
            }
          };
          parent_ingredient.set_is_parent();
          builder.add_ingredient(parent_ingredient);
        }

        let alg = config.signing_alg.to_c2pa();
        let signer = config.signer.resolve(alg)?;

        if let Some(remote_url) = config.remote_manifest_url {
          let allow_http = config.allow_insecure_remote_http.unwrap_or(false);
          validate_external_http_url(&remote_url, allow_http)?;
          builder.set_remote_url(remote_url);
        }
        if !config.embed {
          builder.set_no_embed(true);
        }

        // Choose the appropriate signing method based on input type and output target
        match (&config.source, &config.output) {
          // True streaming: Stream input + Memory output
          (AssetRef::Stream { reader, content_type }, OutputTarget::Memory) => {
            let format = content_type.as_deref().unwrap_or("application/octet-stream");
            let mut source_reader = reader.borrow_mut();
            let mut output_buf = Vec::new();
            let mut output_cursor = std::io::Cursor::new(&mut output_buf);

            let _manifest_bytes = builder.sign(&*signer, format, &mut *source_reader, &mut output_cursor)?;
            Ok(Some(output_buf))
          }

          // File-based or Bytes input with any output
          (AssetRef::Path(_) | AssetRef::Bytes { .. }, _) => {
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
                let meta = std::fs::metadata(&out_path)?;
                if meta.len() as usize > MAX_IN_MEMORY_OUTPUT_SIZE {
                  return Err(EngineError::Config("signed output too large to return in memory".into()));
                }
                let buf = std::fs::read(&out_path)?;
                Ok(Some(buf))
              }
            }
          }

          // Stream input + Path output (true streaming)
          (AssetRef::Stream { reader, content_type }, OutputTarget::Path(dest)) => {
            let format = content_type.as_deref().unwrap_or("application/octet-stream");
            let mut source_reader = reader.borrow_mut();
            let mut output_file = std::fs::File::create(dest)?;

            let _manifest_bytes = builder.sign(&*signer, format, &mut *source_reader, &mut output_file)?;
            Ok(None)
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
      #[cfg(not(feature = "remote_manifests"))]
      {
        if config.allow_remote_manifests {
          return Err(EngineError::Feature("remote_manifests"));
        }
      }
      settings.push(serde_json::json!({
        "verify": { "fetch_remote_manifests": config.allow_remote_manifests }
      }));

      if let Some(policy) = &config.policy {
        let (trust_settings, enable_trust) = Self::build_trust_settings(policy)?;
        settings.extend(trust_settings);
        settings.push(serde_json::json!({
          "verify": { "verify_trust": enable_trust }
        }));
      }

      with_c2pa_settings(&settings, || {
        let reader = match &config.source {
          AssetRef::Stream { reader, content_type } => {
            let format = content_type.as_deref().unwrap_or("application/octet-stream");
            let mut stream = reader.borrow_mut();
            Reader::from_stream(format, &mut *stream)?
          }
          _ => {
            let (src_path, _tmp_dir) = asset_to_temp_path(&config.source)?;
            Reader::from_file(&src_path)?
          }
        };

                let report_str = match config.mode {
                    VerifyMode::Detailed | VerifyMode::Tree => format!("{:?}", reader),
                    VerifyMode::Info | VerifyMode::Summary => format!("{}", reader),
                };

        let (is_embedded_opt, remote_url_opt) = {
          let is_embedded = reader.is_embedded();
          let remote_url = reader.remote_url();
          (Some(is_embedded), remote_url.map(|u| u.to_string()))
        };

        let certificates = if config.include_certificates.unwrap_or(false) {
          reader
            .active_manifest()
            .and_then(|m| m.signature_info())
            .map(|ci| {
              vec![CertInfo {
                alg: ci.alg.map(|a| a.to_string()),
                issuer: ci.issuer.clone(),
                cert_serial_number: ci.cert_serial_number.clone(),
                time: ci.time.clone(),
                revocation_status: ci.revocation_status,
                chain_pem: (!ci.cert_chain.is_empty()).then(|| ci.cert_chain.clone()),
              }]
            })
        } else { None };

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
          is_embedded: is_embedded_opt,
          remote_url: remote_url_opt,
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
        let allow_http = cfg.allow_insecure_remote_http.unwrap_or(false);
        validate_external_http_url(&remote_url, allow_http)?;
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
    match &config.source {
      AssetRef::Stream { reader, content_type } => {
        let format = content_type.as_deref().unwrap_or("application/octet-stream");
        let mut stream = reader.borrow_mut();

        match config.output {
          OutputTarget::Path(dir) => {
            std::fs::create_dir_all(&dir)?;
            // For Path output with streams, we need to create a temp file first
            // since there's no from_stream_with_folder method
            let (temp_path, _temp_dir) = asset_to_temp_path(&config.source)?;
            let report = Ingredient::from_file_with_folder(&temp_path, &dir)?;
            std::fs::write(dir.join("ingredient.json"), report.to_string())?;
            Ok(None)
          }
          OutputTarget::Memory => {
            let ingredient = Ingredient::from_stream(format, &mut *stream)?;
            Ok(Some(ingredient.to_string().into_bytes()))
          }
        }
      }
      _ => {
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
  }
}
