# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-01-15

[Full Changelog](https://github.com/QuePlatform/QueEngine/compare/v0.1.0...v0.1.1)

### Added
- **Configurable File Size Limits**
  - New `LimitsConfig` struct for per-call memory/stream limit customization
  - Added `limits` field to `C2paConfig`, `C2paVerificationConfig`, `IngredientConfig`, `FragmentedBmffConfig`
  - Maintains secure defaults while allowing customization

- **Complete FFI API Surface**
  - Expanded FFI bindings to mirror full Rust API with typed configurations
  - New FFI types: `FfiC2paConfig`, `FfiC2paVerificationConfig`, `FfiLimitsConfig`, structured result types
  - Full enum support for all configuration options
  - Backward compatibility maintained

### Enhanced
- **UniFFI Configuration**
  - Proper scaffolding setup and build dependencies
  - Added `uniffi.toml` for multi-language binding generation
  - Enhanced build system for Swift, Kotlin, and future WASM support

### Fixed
- **FFI Build System**
  - Resolved binding generation issues for Swift and Kotlin
  - Fixed build dependencies and scaffolding setup
  - Documented WASM blocking issue (OpenSSL dependency)

## [0.1.0] - 2025-08-29

[Full Changelog](https://github.com/QuePlatform/QueEngine/commits/v0.1.0)
### Added
- **CAWG Certificate Reuse Enhancement**
  - New `CawgSigner` enum allows reusing main C2PA signer certificates for CAWG identity assertions
  - `CawgSigner::UseMainSigner`: Default behavior - automatically uses same cert/key as main C2PA manifest signer
  - `CawgSigner::Separate(Signer)`: Opt-out option for using separate certificates for CAWG
  - Updated `create_cawg_x509_config()` helper to use `CawgSigner::Separate` for explicit separate certs
  - Enhanced `create_cawg_raw_signer()` to support certificate reuse while honoring CAWG-specific algorithm and timestamp settings
  - Improved API ergonomics: Most users can now enable CAWG with minimal configuration changes

### Enhanced
- **CAWG Security & Safety Improvements**
  - Fixed borrow checker issues in CAWG signer creation
  - Cleaned up unused parameters and improved code organization
  - Enhanced CAWG validation status detection with precise code matching
  - Added comprehensive zeroization of raw certificate material after signer construction
  - Added Unix-specific file permission checks for private key files
  - Improved CAWG signing to support all `AssetRef` input types via temp file conversion

### Added
- **CAWG (Creator Assertions Working Group) Identity Assertions Support**
  - New `cawg` feature flag enables X.509 identity assertions for both signing and verification
  - Supports CAWG v1 specification with X.509 certificate-based identity assertions
  - Requires claim version 2 (automatically enforced when CAWG is used)
  - Signing: Wraps main manifest signer with `AsyncIdentityAssertionSigner` and X.509 credential holder
  - Verification: Validates CAWG identity assertions using `CawgValidator` from c2pa-rs
  - New types: `CawgIdentity`, `CawgVerifyOptions`, `CawgVerification`
  - Secure by default: feature-gated, BYO certificates only, defaults to disabled
  - Helper constructors: `create_cawg_x509_config()`, `create_cawg_verify_options()`
  - Added automatic zeroization of raw certificate and private key material from memory immediately after signer construction
  - Added Unix-specific file permission checks for private key files (rejects group/other-readable keys with insecure permissions)
  - Tightened CAWG status code matching to prevent overmatching with related but different assertion types
  - Enhanced CAWG signing to support streaming input via temp file conversion (previously restricted to files/bytes only)
    - CAWG signing now supports all `AssetRef` input types (Path, Bytes, Stream) instead of just Path/Bytes
  - Improved CAWG validation status detection with more precise code matching patterns
  - Added dependency on `zeroize` crate for secure memory wiping of sensitive cryptographic material

- **Complete C2PA v2 API Migration**
  - Enhanced validation with structured `ValidationResults` instead of flat status arrays
  - Added comprehensive ingredient delta validation support
  - Improved validation status categorization (success, informational, failure)
  - Future-proofed against upcoming v1 API deprecation

- **Streaming & Memory Safety**
  - Production-tuned memory limits to prevent memory exhaustion:
    - Asset size limit: reduced from 512MB to 128MB
    - Output size limit: reduced from 512MB to 128MB
    - Stream copy limit: 1GB max for temp file operations
    - Stream timeout: 5 minutes max for operations
  - Enhanced streaming with `copy_with_limits()` function for size protection
  - True streaming support for `AssetRef::Stream` with `OutputTarget::Path`

- **Content Detection & Validation**
  - Content type auto-detection from stream magic bytes (JPEG, PNG, GIF, WebP, MP4, PDF)
  - Content detection aligned with official C2PA supported formats:
    - Removed support for unsupported formats (ICO, BMP)
    - Added support for all official C2PA formats (AVIF, DNG, HEIC, HEIF, M4A, MOV, SVG, TIFF, WAV)
    - Improved MP4 variant detection (M4A, MOV, fragmented MP4)
    - Updated MIME type detection to match official C2PA specifications

- **Security & Defaults**
  - Enhanced URL validation framework for remote asset fetching
  - DNS/IP hardening for external URLs (TSA and remote manifests), blocking private/loopback/link-local ranges, including via DNS resolution
  - Extension sanitization for in-memory assets (`AssetRef::Bytes.ext`)
  - HTTPS enforcement for TSA and remote manifest URLs with per-call `allow_insecure_remote_http` override (requires `http_urls` feature)
  - Secure default constructors:
    - `C2paConfig::secure_default(...)`
    - `C2paVerificationConfig::secure_default(...)`
    - `IngredientConfig::secure_default(...)`
    - `FragmentedBmffConfig::secure_default(...)`
  - **Centralized defaults model**: New `EngineDefaults` struct with all opinionated defaults for consistency and maintainability
    - All `secure_default()` methods now reference centralized constants instead of hard-coded values
    - `EngineDefaults` is exported in the public API for direct access to default values

- **Refactoring & Code Organization**
  - **C2PA adapter**: Split monolithic `c2pa.rs` (790 lines) into organized modules
    - `constants.rs` - Memory limits and settings
    - `content_detection.rs` - File type detection and content type utilities
    - `url_validation.rs` - Security validation and remote asset handling
    - `asset_utils.rs` - Asset processing and streaming utilities
    - `settings.rs` - C2PA settings management and manifest preparation
    - `engine/` folder with specialized modules:
      - `engine/mod.rs` - Main C2pa struct and ManifestEngine trait implementation
      - `engine/common.rs` - Shared utilities (build_trust_settings, setup_builder, ensure_claim_version_2)
      - `engine/sign.rs` - Signing operations (generate/sign_c2pa)
      - `engine/verify.rs` - Verification operations (verify_c2pa)
      - `engine/ingredient.rs` - Ingredient creation operations
      - `engine/bmff.rs` - Fragmented BMFF operations (generate_fragmented_bmff)
  - **Domain types**: Split monolithic `types.rs` (216 lines) into logical modules
    - `core.rs` - SigAlg, VerifyMode, OutputTarget
    - `asset.rs` - AssetRef and implementations
    - `trust.rs` - TrustPolicyConfig
    - `config.rs` - All configuration structs (C2paConfig, C2paVerificationConfig, etc.)
  - **Maintained identical external APIs** - Zero breaking changes to public interfaces

- **Documentation**
  - `docs/TYPES.md`: Added `AssetRef::Stream` variant with content_type field, memory considerations, and complete list of supported C2PA file formats
  - `README.md`: Added production deployment and API best practices section, plus supported file formats overview
  - Updated README.md with comprehensive defaults summary table and new usage examples showing `EngineDefaults` integration
  - Maintained existing API and FFI documentation as-is

- **Code Cleanup**
  - Removed redundant `detect_content_type_from_stream` function (unused)
  - Kept only `detect_extension_from_bytes` which is actively used
  - Added utility function `extension_to_mime_type` for format conversion
  - Eliminated code duplication while maintaining all functionality

- **Feature Gates**
  - `remote_manifests` (allow fetching remote manifests)
  - `http_urls` (allow HTTP URLs)

- **Verification Options**
  - New option `include_certificates` to opt into returning signing certificate info
  - Added verify-side `verify_identity_trust` support mirroring sign path when a `TrustPolicyConfig` is provided

### Changed
- **C2PA v2 API Migration**
  - Replaced deprecated `reader.validation_status()` with `reader.validation_results()`
  - Updated settings API from `load_settings_from_str()` to `Settings::from_string()`
  - Replaced `CAIRead` trait with standard Rust I/O traits (`Read + Seek + Send`)
  - Fixed type references: `TrustPolicy` → `TrustPolicyConfig`
  - Enhanced validation to process both active manifest and ingredient delta results
  - Maintained full backward compatibility with existing public APIs

- **Streaming & Error Handling**
  - Fixed streaming implementation to truly stream for `Stream + Path` operations
  - Enhanced content type handling with auto-detection for streams
  - Improved error handling for memory limit violations
  - `sign_c2pa_bytes` now returns an error if no memory output is produced (instead of returning empty bytes)

- **Defaults**
  - Default Digicert TSA changed from HTTP to HTTPS: `https://timestamp.digicert.com`
  - Verification defaults remain strict: remote manifest fetching disabled unless explicitly enabled

### Fixed
- **FFI Bindings Generation**
  - Corrected Cargo.toml workspace configuration by removing conflicting `[package]` section
  - Added proper `#[uniffi::export]` attributes to FFI functions (`sign_file_c2pa`, `verify_file_c2pa`)
  - Fixed UniFFI error handling by converting `FfiError` from struct to enum with `#[derive(uniffi::Error)]`
  - Added `#[derive(uniffi::Record)]` to `VerifyOptions` struct for proper FFI serialization
  - Bindings now properly expose: `signFileC2pa()`, `verifyFileC2pa()`, `VerifyOptions`, and `FfiError`

### Removed
- **C2PA v1 API Support**
  - Removed deprecated `v1_api` feature from C2PA dependency
  - No longer possible to enable C2PA v1 API functionality
  - Forces use of C2PA v2 API (which is the default and recommended)
  - Removes access to deprecated methods and structures

- **Built-in Signers**
  - Removed built-in ES256 signer and any bundled PEM usage
  - Only BYO certs are supported via `Signer::Local` and `Signer::Env`

### Breaking Changes
- **C2PA v1 API Removal**
  - Removed deprecated `v1_api` feature from C2PA dependency
  - No longer possible to enable C2PA v1 API functionality
  - Forces migration to C2PA v2 API (which is the default and recommended)
  - Removes access to deprecated methods like `validation_status()` flat arrays

- **Signer Changes**
  - Removal of `Signer::BuiltinEs256` and parsing of `builtin:*` URIs

- **Configuration Changes**
  - New fields added to configs (constructors updated accordingly):
    - `C2paConfig.allow_insecure_remote_http: Option<bool>`
    - `C2paVerificationConfig.include_certificates: Option<bool>`
    - `FragmentedBmffConfig.allow_insecure_remote_http: Option<bool>`

- **Memory Limits**
  - Reduced memory limits may cause failures for previously working large assets:
    - Asset size limit: 512MB → 128MB
    - Output size limit: 512MB → 128MB