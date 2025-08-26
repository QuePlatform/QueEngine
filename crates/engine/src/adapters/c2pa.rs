// crates/engine/src/adapters/c2pa.rs
#[cfg(feature = "c2pa")]
use c2pa::{Ingredient, Reader};

use once_cell::sync::Lazy;
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;
use std::net::IpAddr;
use url::{Host, Url};
use std::net::ToSocketAddrs;

use crate::crypto::timestamper::Timestamper;
use crate::domain::error::{EngineError, EngineResult};
use crate::domain::manifest_engine::ManifestEngine;
use crate::domain::types::{
  AssetRef, C2paConfig, C2paVerificationConfig, OutputTarget, VerifyMode,
};
use crate::domain::verify::{CertInfo, ValidationStatus, VerificationResult, Verdict};

static C2PA_SETTINGS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static BASE_SETTINGS: &str = r#"{}"#;

const MAX_IN_MEMORY_ASSET_SIZE: usize = 512 * 1024 * 1024; // 512 MB
const MAX_IN_MEMORY_OUTPUT_SIZE: usize = 512 * 1024 * 1024; // 512 MB

fn validate_external_http_url(url_str: &str, allow_http: bool) -> EngineResult<()> {
  let url = Url::parse(url_str)
    .map_err(|_| EngineError::Config("invalid URL".into()))?;
  match url.scheme() {
    "https" => {}
    "http" => {
      #[cfg(not(feature = "http_urls"))]
      {
        if !allow_http { return Err(EngineError::Config("HTTP URLs are not allowed".into())); }
        return Err(EngineError::Feature("http_urls"));
      }
      #[cfg(feature = "http_urls")]
      {
        if !allow_http { return Err(EngineError::Config("HTTP URLs are not allowed".into())); }
      }
    }
    _ => return Err(EngineError::Config("unsupported URL scheme".into())),
  }
  let host = url.host().ok_or_else(|| EngineError::Config("URL missing host".into()))?;
  if let Some(ip) = match host {
    Host::Ipv4(a) => Some(IpAddr::V4(a)),
    Host::Ipv6(a) => Some(IpAddr::V6(a)),
    Host::Domain(_) => None,
  } {
    let is_blocked = match ip {
      IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_documentation() || v4.is_unspecified(),
      IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_unspecified() || v6.is_multicast(),
    };
    if is_blocked {
      return Err(EngineError::Config("URL host is not allowed (private/link-local/loopback)".into()));
    }
  }
  // DNS resolution hardening: block domains resolving to private/link-local IPs
  if let Some(domain) = url.host_str() {
    let default_port = match url.scheme() { "https" => 443, "http" => 80, _ => 0 };
    if default_port != 0 {
      if let Ok(addrs) = (domain, default_port).to_socket_addrs() {
        for addr in addrs {
          let ip = addr.ip();
          let is_blocked = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_documentation() || v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_unspecified() || v6.is_multicast(),
          };
          if is_blocked {
            return Err(EngineError::Config("URL resolves to a disallowed private/loopback address".into()));
          }
        }
      }
    }
  }
  Ok(())
}

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
            let allow_http = false; // default secure: no HTTP
            validate_external_http_url(&url, allow_http)?;
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
          validate_external_http_url(&url, allow_http)?;
          manifest_val["ta_url"] = Value::String(url);
        }
      }
      Ok(serde_json::to_string(&manifest_val)?)
    }
  }
}

fn detect_extension_from_bytes(data: &[u8]) -> Option<&'static str> {
  // JPEG
  if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
    return Some("jpg");
  }
  // PNG
  if data.len() >= 8 && data[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
    return Some("png");
  }
  // GIF
  if data.len() >= 6 && (&data[..6] == b"GIF87a" || &data[..6] == b"GIF89a") {
    return Some("gif");
  }
  // WEBP / RIFF-based
  if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
    return Some("webp");
  }
  // WAV
  if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
    return Some("wav");
  }
  // AVI
  if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"AVI " {
    return Some("avi");
  }
  // TIFF (II*\0 or MM\0*)
  if data.len() >= 4 && ((&data[..4] == b"II*\0") || (&data[..4] == b"MM\0*")) {
    return Some("tiff");
  }
  // MP4/MOV/ISO-BMFF (ftyp box)
  if data.len() >= 12 && &data[4..8] == b"ftyp" {
    // Heuristic brands
    if data.len() >= 16 {
      let brand = &data[8..12];
      if brand == b"heic" || brand == b"heif" { return Some("heic"); }
      if brand == b"avif" { return Some("avif"); }
      if brand == b"mp42" || brand == b"isom" || brand == b"qt  " { return Some("mp4"); }
    }
    return Some("mp4");
  }
  // PDF
  if data.len() >= 5 && &data[..5] == b"%PDF-" {
    return Some("pdf");
  }
  // SVG (very loose check: starts with '<' and contains "<svg" early)
  if data.len() >= 5 && data[0] == b'<' {
    let head = &data[..std::cmp::min(512, data.len())];
    if let Ok(s) = std::str::from_utf8(head) {
      if s.to_ascii_lowercase().contains("<svg") {
        return Some("svg");
      }
    }
  }
  // ICO
  if data.len() >= 4 && &data[..4] == [0x00, 0x00, 0x01, 0x00] {
    return Some("ico");
  }
  // BMP
  if data.len() >= 2 && &data[..2] == b"BM" {
    return Some("bmp");
  }
  // MP3 (ID3 tag or frame sync 0xFFEx)
  if data.len() >= 3 && &data[..3] == b"ID3" {
    return Some("mp3");
  }
  if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
    return Some("mp3");
  }
  None
}

fn asset_to_temp_path(
  asset: &AssetRef,
) -> EngineResult<(std::path::PathBuf, Option<tempfile::TempDir>)> {
  match asset {
    AssetRef::Path(p) => Ok((p.clone(), None)),
    AssetRef::Bytes { data } => {
      if data.len() > MAX_IN_MEMORY_ASSET_SIZE {
        return Err(EngineError::Config("in-memory asset too large".into()));
      }
      let dir = tempfile::tempdir()?;
      let filename = if let Some(ext) = detect_extension_from_bytes(data) {
        format!("asset.{ext}")
      } else {
        "asset".to_string()
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
          let allow_http = config.allow_insecure_remote_http.unwrap_or(false);
          validate_external_http_url(&remote_url, allow_http)?;
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
            // Use a generic output filename; c2pa determines correct handling.
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
        settings.push(serde_json::json!({
          "verify": { "verify_trust": enable_trust }
        }));
        if let Some(v) = policy.verify_identity_trust {
          settings.push(serde_json::json!({
            "verify": { "verify_identity_trust": v }
          }));
        }
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
                chain_pem: if ci.cert_chain.is_empty() {
                  None
                } else {
                  Some(ci.cert_chain.clone())
                },
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