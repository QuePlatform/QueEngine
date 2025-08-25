## [Unreleased]

### Added
- Secure default constructors: `C2paConfig::secure_default(...)` and `C2paVerificationConfig::secure_default(...)`.
- Feature gates: `remote_manifests` (allow fetching remote manifests) and `http_urls` (allow HTTP URLs).
- Verification option `include_certificates` to opt into returning signing certificate info.
- DNS/IP hardening for external URLs (TSA and remote manifests), blocking private/loopback/link-local ranges, including via DNS resolution.
- Extension sanitization for in-memory assets (`AssetRef::Bytes.ext`).
- HTTPS enforcement for TSA and remote manifest URLs with per-call `allow_insecure_remote_http` override (requires `http_urls` feature).

### Changed
- `sign_c2pa_bytes` now returns an error if no memory output is produced (instead of returning empty bytes).
- Default Digicert TSA changed from HTTP to HTTPS: `https://timestamp.digicert.com`.
- Verification defaults remain strict: remote manifest fetching disabled unless explicitly enabled.
- Added verify-side `verify_identity_trust` support mirroring sign path when a `TrustPolicyConfig` is provided.

### Removed
- Built-in ES256 signer and any bundled PEM usage. Only BYO certs are supported via `Signer::Local` and `Signer::Env`.

### Breaking changes
- Removal of `Signer::BuiltinEs256` and parsing of `builtin:*` URIs.
- New fields added to configs (constructors updated accordingly):
  - `C2paConfig.allow_insecure_remote_http: Option<bool>`
  - `C2paVerificationConfig.include_certificates: Option<bool>`
  - `FragmentedBmffConfig.allow_insecure_remote_http: Option<bool>`

### Migration guide
- Replace any `builtin:es256` usage with either `local:/path/cert.pem,/path/key.pem` or `env:CERT_PEM,KEY_PEM`.
- If you previously relied on remote manifest fetching, compile with `remote_manifests` and set `C2paVerificationConfig.allow_remote_manifests = true`.
- If you need HTTP URLs (discouraged), compile with `http_urls` and set `allow_insecure_remote_http = Some(true)` on the respective config.


