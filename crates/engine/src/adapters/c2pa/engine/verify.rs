// adapters/c2pa/engine/verify.rs

#[cfg(feature = "c2pa")]
use c2pa::Reader;

use crate::domain::error::{EngineError, EngineResult};
use crate::domain::types::{AssetRef, C2paVerificationConfig, VerifyMode};
use crate::domain::verify::{
  CertInfo, ValidationStatus, VerificationResult, Verdict,
};
use super::super::asset_utils::asset_to_temp_path;
use super::super::settings::with_c2pa_settings;

#[cfg(feature = "cawg")]
use super::super::cawg;
use super::common::{build_trust_settings, run_on_current_thread};

pub fn verify_c2pa(
  config: C2paVerificationConfig,
) -> EngineResult<VerificationResult> {
  #[cfg(not(feature = "c2pa"))]
  {
    return Err(EngineError::Feature("c2pa"));
  }
  #[cfg(feature = "c2pa")]
  {
    let mut settings = Vec::<serde_json::Value>::new();

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
      let (trust_settings, enable_trust) = build_trust_settings(policy)?;
      settings.extend(trust_settings);
      settings.push(serde_json::json!({
        "verify": { "verify_trust": enable_trust }
      }));
    }

    with_c2pa_settings(&settings, || {
      let mut reader = match &config.source {
        AssetRef::Stream { reader, content_type } => {
          let format = content_type
            .as_deref()
            .unwrap_or("application/octet-stream");
          let mut stream = reader.borrow_mut();
          Reader::from_stream(format, &mut *stream)?
        }
        _ => {
          let (src_path, _tmp_dir) = asset_to_temp_path(&config.source, config.limits)?;
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
      } else {
        None
      };

      let status_vec = reader.validation_results().map(|results| {
        let mut all_statuses = Vec::new();

        if let Some(active_manifest) = results.active_manifest() {
          for status in active_manifest.success() {
            all_statuses.push(ValidationStatus {
              code: status.code().to_string(),
              url: status.url().map(|u| u.to_string()),
              explanation: status.explanation().map(|e| e.to_string()),
              ingredient_uri: status.ingredient_uri().map(|i| i.to_string()),
              passed: status.passed(),
            });
          }
          for status in active_manifest.informational() {
            all_statuses.push(ValidationStatus {
              code: status.code().to_string(),
              url: status.url().map(|u| u.to_string()),
              explanation: status.explanation().map(|e| e.to_string()),
              ingredient_uri: status.ingredient_uri().map(|i| i.to_string()),
              passed: status.passed(),
            });
          }
          for status in active_manifest.failure() {
            all_statuses.push(ValidationStatus {
              code: status.code().to_string(),
              url: status.url().map(|u| u.to_string()),
              explanation: status.explanation().map(|e| e.to_string()),
              ingredient_uri: status.ingredient_uri().map(|i| i.to_string()),
              passed: status.passed(),
            });
          }
        }

        if let Some(ingredient_deltas) = results.ingredient_deltas() {
          for delta_result in ingredient_deltas {
            let validation_deltas = delta_result.validation_deltas();
            for status in validation_deltas.success() {
              all_statuses.push(ValidationStatus {
                code: status.code().to_string(),
                url: status.url().map(|u| u.to_string()),
                explanation: status.explanation().map(|e| e.to_string()),
                ingredient_uri: status.ingredient_uri().map(|i| i.to_string()),
                passed: status.passed(),
              });
            }
            for status in validation_deltas.informational() {
              all_statuses.push(ValidationStatus {
                code: status.code().to_string(),
                url: status.url().map(|u| u.to_string()),
                explanation: status.explanation().map(|e| e.to_string()),
                ingredient_uri: status.ingredient_uri().map(|i| i.to_string()),
                passed: status.passed(),
              });
            }
            for status in validation_deltas.failure() {
              all_statuses.push(ValidationStatus {
                code: status.code().to_string(),
                url: status.url().map(|u| u.to_string()),
                explanation: status.explanation().map(|e| e.to_string()),
                ingredient_uri: status.ingredient_uri().map(|i| i.to_string()),
                passed: status.passed(),
              });
            }
          }
        }

        all_statuses
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

      #[cfg(feature = "cawg")]
      let cawg_verification: Option<crate::domain::cawg::CawgVerification> =
        if let Some(cawg_opts) = &config.cawg {
          if cawg_opts.validate {
            Some(run_on_current_thread(cawg::validate_cawg(&mut reader, cawg_opts))?)
          } else {
            None
          }
        } else {
          None
        };

      #[cfg(feature = "cawg")]
      {
        if let (Some(cawg_opts), Some(cawg_result)) =
          (&config.cawg, &cawg_verification)
        {
          if cawg_opts.require_valid_identity
            && (!cawg_result.present || !cawg_result.valid)
          {
            return Err(EngineError::VerificationFailed);
          }
        }
      }

      Ok(VerificationResult {
        report: report_str,
        certificates,
        status: status_vec,
        verdict,
        is_embedded: is_embedded_opt,
        remote_url: remote_url_opt,
        #[cfg(feature = "cawg")]
        cawg: cawg_verification,
      })
    })
  }
}