// adapters/c2pa/engine/common.rs

#[cfg(feature = "c2pa")]
use c2pa::Ingredient;

use crate::domain::error::{EngineError, EngineResult};
use crate::domain::types::{AssetRef, C2paConfig, TrustPolicyConfig};
use super::super::url_validation::validate_external_http_url;

pub fn build_trust_settings(
  policy: &TrustPolicyConfig,
) -> EngineResult<(Vec<serde_json::Value>, bool)> {
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

  // Optional: only keep this if the field exists in your TrustPolicyConfig
  #[allow(unused)]
  if let Some(v) = policy.verify_identity_trust {
    settings.push(serde_json::json!({
      "verify": { "verify_identity_trust": v }
    }));
  }

  Ok((settings, enable_trust))
}

#[cfg(feature = "cawg")]
pub fn ensure_claim_version_2(
  manifest_json: String,
) -> EngineResult<String> {
  let mut manifest: serde_json::Value = serde_json::from_str(&manifest_json)
    .map_err(|e| EngineError::Config(format!("Invalid manifest JSON: {}", e)))?;

  if let Some(obj) = manifest.as_object_mut() {
    obj.insert(
      "claim_version".to_string(),
      serde_json::Value::Number(2.into()),
    );
  }

  serde_json::to_string(&manifest)
    .map_err(|e| EngineError::Config(format!("Failed to serialize manifest: {}", e)))
}

#[cfg(feature = "c2pa")]
pub fn setup_builder(
  builder: &mut c2pa::Builder,
  config: &C2paConfig,
) -> EngineResult<()> {
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
        return Err(EngineError::Config(
          "parent ingredients from streams are not currently supported".into(),
        ));
      }
    };
    parent_ingredient.set_is_parent();
    builder.add_ingredient(parent_ingredient);
  }

  if let Some(ref remote_url) = config.remote_manifest_url {
    let allow_http = config.allow_insecure_remote_http.unwrap_or(false);
    validate_external_http_url(remote_url, allow_http)?;
    builder.set_remote_url(remote_url.clone());
  }
  if !config.embed {
    builder.set_no_embed(true);
  }

  Ok(())
}

pub fn run_on_current_thread<F, T>(fut: F) -> EngineResult<T>
where
  F: std::future::Future<Output = EngineResult<T>>,
{
  // If we're already inside a Tokio runtime, avoid creating a nested runtime.
  // Use block_in_place to safely block on the current multi-thread runtime.
  if let Ok(handle) = tokio::runtime::Handle::try_current() {
    return tokio::task::block_in_place(|| handle.block_on(fut));
  }

  // Otherwise, create a lightweight current-thread runtime just for this call.
  let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .map_err(|e| EngineError::Config(format!("Failed to create tokio runtime: {}", e)))?;
  rt.block_on(fut)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn run_on_current_thread_outside_runtime() {
    let res: EngineResult<()> = run_on_current_thread(async { Ok(()) });
    assert!(res.is_ok());
  }

  #[test]
  fn run_on_current_thread_inside_multithread_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
      .enable_all()
      .build()
      .expect("build rt");
    let res: EngineResult<()> = rt.block_on(async {
      run_on_current_thread(async { Ok(()) })
    });
    assert!(res.is_ok());
  }
}