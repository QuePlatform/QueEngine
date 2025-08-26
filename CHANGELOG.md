## [Unreleased]

### Added
- Production-tuned memory limits to prevent memory exhaustion:
  - Asset size limit: reduced from 512MB to 128MB
  - Output size limit: reduced from 512MB to 128MB
  - Stream copy limit: 1GB max for temp file operations
  - Stream timeout: 5 minutes max for operations
- Enhanced streaming with `copy_with_limits()` function for size protection
- True streaming support for `AssetRef::Stream` with `OutputTarget::Path`
- Content type auto-detection from stream magic bytes (JPEG, PNG, GIF, WebP, MP4, PDF)
- Enhanced URL validation framework for remote asset fetching
- Production API best practices documentation in README.md
- **Modular refactoring for better code organization:**
  - **C2PA adapter**: Split monolithic `c2pa.rs` (790 lines) into organized modules
    - `constants.rs` - Memory limits and settings
    - `content_detection.rs` - File type detection and content type utilities
    - `url_validation.rs` - Security validation and remote asset handling
    - `asset_utils.rs` - Asset processing and streaming utilities
    - `settings.rs` - C2PA settings management and manifest preparation
    - `engine.rs` - Main C2pa struct and core business logic
  - **Domain types**: Split monolithic `types.rs` (216 lines) into logical modules
    - `core.rs` - SigAlg, VerifyMode, OutputTarget
    - `asset.rs` - AssetRef and implementations
    - `trust.rs` - TrustPolicyConfig
    - `config.rs` - All configuration structs (C2paConfig, C2paVerificationConfig, etc.)
  - **Maintained identical external APIs** - Zero breaking changes to public interfaces
- Updated documentation:
  - `docs/TYPES.md`: Added AssetRef::Stream variant with content_type field, memory considerations, and complete list of supported C2PA file formats
  - `README.md`: Added production deployment and API best practices section, plus supported file formats overview
  - Maintained existing API and FFI documentation as-is
- Content detection aligned with official C2PA supported formats:
  - Removed support for unsupported formats (ICO, BMP)
  - Added support for all official C2PA formats (AVIF, DNG, HEIC, HEIF, M4A, MOV, SVG, TIFF, WAV)
  - Improved MP4 variant detection (M4A, MOV, fragmented MP4)
  - Updated MIME type detection to match official C2PA specifications
- **Code cleanup and deduplication:**
  - Removed redundant `detect_content_type_from_stream` function (unused)
  - Kept only `detect_extension_from_bytes` which is actively used
  - Added utility function `extension_to_mime_type` for format conversion
  - Eliminated code duplication while maintaining all functionality
- Secure default constructors: `C2paConfig::secure_default(...)`, `C2paVerificationConfig::secure_default(...)`, `IngredientConfig::secure_default(...)`, and `FragmentedBmffConfig::secure_default(...)`.
- Feature gates: `remote_manifests` (allow fetching remote manifests) and `http_urls` (allow HTTP URLs).
- Verification option `include_certificates` to opt into returning signing certificate info.
- DNS/IP hardening for external URLs (TSA and remote manifests), blocking private/loopback/link-local ranges, including via DNS resolution.
- Extension sanitization for in-memory assets (`AssetRef::Bytes.ext`).
- HTTPS enforcement for TSA and remote manifest URLs with per-call `allow_insecure_remote_http` override (requires `http_urls` feature).
- **Centralized defaults model**: New `EngineDefaults` struct with all opinionated defaults for consistency and maintainability. All `secure_default()` methods now reference centralized constants instead of hard-coded values. `EngineDefaults` is exported in the public API for direct access to default values.
- Updated README.md with comprehensive defaults summary table and new usage examples showing `EngineDefaults` integration.

### Changed
- Refactored monolithic `c2pa.rs` (790 lines) into modular structure:
  - `constants.rs` - Memory limits and settings
  - `content_detection.rs` - File type detection
  - `url_validation.rs` - Security validation
  - `asset_utils.rs` - Asset processing utilities
  - `settings.rs` - Configuration management
  - `engine.rs` - Core business logic
- Fixed streaming implementation to truly stream for `Stream + Path` operations
- Enhanced content type handling with auto-detection for streams
- Improved error handling for memory limit violations
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
- Reduced memory limits may cause failures for previously working large assets:
  - Asset size limit: 512MB → 128MB
  - Output size limit: 512MB → 128MB

### Migration guide
- Replace any `builtin:es256` usage with either `local:/path/cert.pem,/path/key.pem` or `env:CERT_PEM,KEY_PEM`.
- If you previously relied on remote manifest fetching, compile with `remote_manifests` and set `C2paVerificationConfig.allow_remote_manifests = true`.
- If you need HTTP URLs (discouraged), compile with `http_urls` and set `allow_insecure_remote_http = Some(true)` on the respective config.
- For large assets (>128MB), use `AssetRef::Stream` instead of `AssetRef::Bytes`
- For large output files, use `OutputTarget::Path` instead of `OutputTarget::Memory`
- Handle new error types for memory limit violations:
  - `Config("in-memory asset too large")` - Asset exceeds 128MB
  - `Config("signed output too large to return in memory")` - Output exceeds 128MB
  - `Config("Stream size limit exceeded")` - Stream copy exceeds 1GB


