use std::net::IpAddr;
use url::{Host, Url};
use std::net::ToSocketAddrs;

use crate::domain::error::{EngineError, EngineResult};

pub fn validate_external_http_url(url_str: &str, allow_http: bool) -> EngineResult<()> {
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

/// Enhanced URL validation for production use with content fetching policies
/// This function should be called BEFORE fetching any remote asset
pub fn validate_and_fetch_remote_asset(
  url_str: &str,
  allowed_http: bool,
  _max_content_length: Option<u64>,
) -> EngineResult<(String, Vec<u8>)> {
  // First validate the URL structure and security
  validate_external_http_url(url_str, allowed_http)?;

  // Parse URL for additional checks
  let _url = Url::parse(url_str)
    .map_err(|_| EngineError::Config("invalid URL".into()))?;

  // Only allow specific MIME types that we support
  let _supported_types = [
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "video/mp4", "audio/mpeg", "application/pdf"
  ];

  // For now, return a placeholder - actual implementation would:
  // 1. Make HEAD request to check Content-Length and Content-Type
  // 2. Validate against max_content_length (default 1GB)
  // 3. Check Content-Type against supported_types
  // 4. Fetch with timeout and size limits
  // 5. Store to temp file and return AssetRef::Path

  Err(EngineError::Config("Remote asset fetching not yet implemented - use AssetRef::Path after secure fetching".into()))
}
