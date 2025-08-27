// adapters/c2pa/engine/bmff.rs

#[cfg(all(feature = "c2pa", feature = "bmff"))]
use c2pa::Builder;

use crate::domain::error::{EngineError, EngineResult};
use super::super::settings::{with_c2pa_settings, prepare_manifest_json};
use super::super::url_validation::validate_external_http_url;

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