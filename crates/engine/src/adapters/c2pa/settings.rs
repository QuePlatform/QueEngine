use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::domain::error::{EngineError, EngineResult};
use crate::crypto::timestamper::Timestamper;
use super::constants::{C2PA_SETTINGS_LOCK, BASE_SETTINGS};

#[cfg(feature = "c2pa")]
use c2pa::settings::Settings;

pub fn apply_settings(jsons: &[serde_json::Value]) -> EngineResult<()> {
  #[cfg(not(feature = "c2pa"))]
  {
    return Err(EngineError::Feature("c2pa"));
  }
  #[cfg(feature = "c2pa")]
  {
    // For JSON content, we need to use from_string with json format

    let _ = Settings::from_string(BASE_SETTINGS, "json")?;
    for s in jsons {
      let _ = Settings::from_string(&s.to_string(), "json")?;
    }
    Ok(())
  }
}

pub fn with_c2pa_settings<F, T>(settings: &[serde_json::Value], f: F) -> EngineResult<T>
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
  let _ = Settings::from_string(BASE_SETTINGS, "json");

  match result {
    Ok(r) => r,
    Err(_) => Err(EngineError::Panic("c2pa adapter panicked".into())),
  }
}

pub fn prepare_manifest_json(
  manifest_definition: Option<String>,
  timestamper: &Option<Timestamper>,
) -> EngineResult<String> {
  match manifest_definition {
    Some(json_str) => {
      if let Some(tsa) = timestamper {
        let mut manifest_val: Value = serde_json::from_str(&json_str)?;
        if let Some(obj) = manifest_val.as_object_mut() {
          if let Some(url) = tsa.resolve() {
            let allow_http = false; // default secure: no HTTP
            super::url_validation::validate_external_http_url(&url, allow_http)?;
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
          let allow_http = false; // default secure: no HTTP
          super::url_validation::validate_external_http_url(&url, allow_http)?;
          manifest_val["ta_url"] = Value::String(url);
        }
      }
      Ok(serde_json::to_string(&manifest_val)?)
    }
  }
}
