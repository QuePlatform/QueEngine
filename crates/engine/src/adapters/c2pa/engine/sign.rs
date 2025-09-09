// adapters/c2pa/engine/sign.rs

use crate::domain::error::{EngineError, EngineResult};
use crate::domain::types::{AssetRef, C2paConfig, OutputTarget};
use super::super::settings::{with_c2pa_settings, prepare_manifest_json};
use super::super::asset_utils::{asset_to_temp_path, sniff_content_type_from_reader};

#[cfg(feature = "cawg")]
use super::super::cawg;
#[cfg(feature = "cawg")]
use super::common::ensure_claim_version_2;

use super::common::{build_trust_settings, run_on_current_thread, setup_builder};


pub fn sign_c2pa(config: C2paConfig) -> EngineResult<Option<Vec<u8>>> {
  #[cfg(not(feature = "c2pa"))]
  {
    return Err(EngineError::Feature("c2pa"));
  }
  #[cfg(feature = "c2pa")]
  {
    let mut settings = vec![serde_json::json!({
      "verify": { "verify_after_sign": !config.skip_post_sign_validation }
    })];

    if let Some(policy) = &config.trust_policy {
      let (trust_settings, enable_trust) = build_trust_settings(policy)?;
      settings.extend(trust_settings);
      settings.push(serde_json::json!({
        "verify": { "verify_trust": enable_trust }
      }));
    }

    with_c2pa_settings(&settings, || {
      let manifest_json =
        prepare_manifest_json(config.manifest_definition.clone(), &config.timestamper)?;

      let alg = config.signing_alg.to_c2pa();

      // CAWG path (async)
      #[cfg(feature = "cawg")]
      if let Some(cawg_identity) = &config.cawg_identity {
        let manifest_json = ensure_claim_version_2(manifest_json)?;
        return run_on_current_thread(async {
          let mut builder = c2pa::Builder::from_json(&manifest_json)?;
          super::common::setup_builder(&mut builder, &config)?;

          let timestamp_url = config.timestamper.as_ref().and_then(|t| t.resolve());

          let signer = cawg::create_cawg_signer(
            &config.signer,
            alg,
            timestamp_url,
            cawg_identity,
          )
          .await?;

          // Support all input types by converting to a temp path when needed
          let (src_path, _tmp_src_dir) = asset_to_temp_path(&config.source, config.limits)?;
          match &config.output {
            OutputTarget::Path(dest) => {
              builder.sign_file_async(&*signer, &src_path, dest).await?;
              Ok(None)
            }
            OutputTarget::Memory => {
              let temp_dir = tempfile::tempdir()?;
              let temp_path = temp_dir.path().join("signed_asset");
              builder.sign_file_async(&*signer, &src_path, &temp_path).await?;
              let buf = std::fs::read(&temp_path)?;
              if buf.len() > config.limits.max_in_memory_output_size {
                return Err(EngineError::Config(
                  "signed output too large to return in memory".into(),
                ));
              }
              Ok(Some(buf))
            }
          }
        });
      }

      // Non-CAWG sync path
      let mut builder = c2pa::Builder::from_json(&manifest_json)?;
      setup_builder(&mut builder, &config)?;

      let signer = config.signer.resolve(alg)?;

      match (&config.source, &config.output) {
        (AssetRef::Stream { reader, content_type }, OutputTarget::Memory) => {
          let mut source_reader = reader.borrow_mut();
          let sniffed = sniff_content_type_from_reader(&mut *source_reader);
          let format = content_type
            .as_deref()
            .or(sniffed)
            .unwrap_or("application/octet-stream");
          let mut output_buf = Vec::new();
          let mut output_cursor = std::io::Cursor::new(&mut output_buf);

          let _manifest_bytes = builder.sign(
            &*signer,
            format,
            &mut *source_reader,
            &mut output_cursor,
          )?;
          Ok(Some(output_buf))
        }

        (AssetRef::Path(_) | AssetRef::Bytes { .. }, _) => {
          let (src_path, _tmp_src_dir) = asset_to_temp_path(&config.source, config.limits)?;
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
              if meta.len() as usize > config.limits.max_in_memory_output_size {
                return Err(EngineError::Config(
                  "signed output too large to return in memory".into(),
                ));
              }
              let buf = std::fs::read(&out_path)?;
              Ok(Some(buf))
            }
          }
        }

        (AssetRef::Stream { reader, content_type }, OutputTarget::Path(dest)) => {
          let mut source_reader = reader.borrow_mut();
          let sniffed = sniff_content_type_from_reader(&mut *source_reader);
          let format = content_type
            .as_deref()
            .or(sniffed)
            .unwrap_or("application/octet-stream");
          let mut output_file = std::fs::File::create(dest)?;

          let _manifest_bytes = builder.sign(
            &*signer,
            format,
            &mut *source_reader,
            &mut output_file,
          )?;
          Ok(None)
        }
      }
    })
  }
}