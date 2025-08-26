# QueEngine

## 1. Overview

**QueEngine** is a high-level, configurable Rust library designed to be the core provenance and authenticity engine for the Que Platform. Its primary function is to provide a safe, robust, and developer-friendly interface for interacting with the C2PA (Coalition for Content Provenance and Authenticity) standard.

While the official `c2pa-rs` library is powerful, it is a low-level toolkit. QueEngine acts as an abstraction layer on top of it, providing:

- **Safe Defaults:** Common operations like signing and verifying work out-of-the-box with secure, opinionated defaults.
- **Powerful Configuration:** Exposes the full power of the underlying C2PA library through well-structured configuration objects, allowing advanced users to customize every aspect of the process.
- **Clear Boundaries:** A clean separation between pure domain logic and concrete implementation details (the "adapter" pattern).
- **Security & Stability:** Manages thread-safety for global settings and provides robust error handling to prevent panics from crossing FFI boundaries.

- **Language SDKs (FFI):** The `que-ffi` crate within this repository uses QueEngine to generate native bindings for Swift (iOS/macOS) and Kotlin (Android), enabling on-device, offline provenance operations.

### 1.2. Core Concepts

#### Domain-Adapter Architecture

The engine is split into two main concepts:

- `domain`: This module contains pure Rust types, traits, and error definitions. It has no knowledge of C2PA or any other specific implementation. It defines *what* the engine can do (e.g., `ManifestEngine` trait).
- `adapters`: This module provides the concrete implementation. The `c2pa.rs` adapter implements the `ManifestEngine` trait using the `c2pa-rs` library. This design allows for future adapters (e.g., for blockchain anchoring) to be added without changing the core domain.

#### Thread-Safe Settings Management

The underlying `c2pa-rs` library relies on a global static configuration for certain settings (like trust validation). Modifying this from multiple threads is unsafe.

**Assumption:** To solve this, QueEngine uses a global `Mutex` (`C2PA_SETTINGS_LOCK`). Any function that needs to modify these global settings (like `verify` with a custom policy) will lock the mutex, apply the settings for the duration of the call, and then restore the baseline settings before releasing the lock. This serializes all settings-dependent C2PA calls, ensuring thread safety at the cost of some parallelism for those specific operations.

### 1.3. Security posture and defaults

- HTTPS is enforced by default for all network URLs (timestamp authority, remote manifests). HTTP can be explicitly opted-in behind a feature and per-call flag.
- Remote manifest fetching is disabled by default; it can be explicitly opted-in behind a feature and per-call flag.
- DNS hardening prevents requests to private/loopback/link-local IP ranges, including resolutions via domain names (mitigates SSRF/DNS rebinding).
- Certificate chain inclusion in verification results is opt-in.
- No built-in or test certificates are bundled. You must bring your own certificates/keys for signing.

### 1.4. Opinionated Defaults Summary

QueEngine follows a "secure by default" philosophy with sensible defaults that can be explicitly opted out of when needed.

All defaults are centralized in the `EngineDefaults` struct for consistency and maintainability. The `secure_default()` methods on all config structs use these centralized defaults.

| Feature | Default | Opt-in Method | Rationale |
|---------|---------|---------------|-----------|
| **HTTPS enforcement** | ✅ Enabled | Feature flag `http_urls` | Security baseline |
| **Remote manifests** | ❌ Disabled | Feature flag `remote_manifests` + `allow_remote_manifests: true` | Network security |
| **HTTP URLs** | ❌ Disabled | `allow_insecure_remote_http: Some(true)` | SSL/TLS security |
| **Memory limits** | ✅ 128MB assets | Hard-coded (not configurable) | Resource exhaustion protection |
| **Trust verification** | ❌ Disabled | Provide `TrustPolicyConfig` | Bring-your-own-trust |
| **Certificate inclusion** | ❌ Disabled | `include_certificates: Some(true)` | Privacy protection |
| **Embed manifests** | ✅ Enabled | `embed: false` | Standard C2PA behavior |
| **Post-sign validation** | ✅ Enabled | `skip_post_sign_validation: true` | Quality assurance |
| **File input method** | `AssetRef::Bytes` | `AssetRef::Path`, `AssetRef::Stream` | Memory efficiency |
| **Output method** | `OutputTarget::Memory` | `OutputTarget::Path` | API convenience |
| **Signing algorithm** | `SigAlg::Es256` | `SigAlg::Es384`, `Ps256`, `Ed25519` | Compatibility |
| **Verification mode** | `VerifyMode::Summary` | `VerifyMode::Info`, `Detailed`, `Tree` | Performance |
| **Timestamping** | ❌ Disabled | Provide `Timestamper` | Cost control |

#### Feature Gating

QueEngine is heavily feature-gated to produce minimal binaries for different targets. This is critical for security and performance. For example, the `enclave` feature (for on-device signing) should never be compiled into the `QueCloud` server binary, and the `kms` feature (for cloud signing) should never be compiled into a device-side library.

See the **Feature Flags** section for a complete list.

## 2. Getting Started

Add QueEngine to your project's `Cargo.toml`.

```toml
[dependencies]
que-engine = { path = "../Engine/crates/engine" }
```

**To include support for fragmented BMFF (MP4) files:**
```toml
[dependencies]
que-engine = { path = "../Engine/crates/engine", features = ["bmff"] }
```

### 2.1 Feature flags

Add features you need to your dependency declaration:

- `c2pa` (default): Enable the C2PA adapter.
- `openssl` (default): Use OpenSSL backend where applicable.
- `bmff`: Support fragmented BMFF signing helpers.
- `remote_manifests` (opt-in): Allow fetching remote manifests during verification. Default is disabled.
- `http_urls` (opt-in): Allow HTTP (non-HTTPS) URLs for TSA/remote manifests. Default is disabled.

Example:
```toml
[dependencies]
que-engine = { path = "../Engine/crates/engine", features = ["bmff", "remote_manifests"] }
```

### 2.2 Bring-your-own certificates (BYO)

QueEngine does not ship any certificates/keys. Provide your own via:

- `Signer::Local { cert_path, key_path }` (URI format: `local:/path/cert.pem,/path/key.pem`)
- `Signer::Env { cert_var, key_var }` (URI format: `env:CERT_ENV,KEY_ENV` where env vars contain PEM content)

Example (env):
```bash
export CERT_PEM="$(cat /path/to/cert.pem)"
export KEY_PEM="$(cat /path/to/key.pem)"
```

If your infrastructure is not prepared to manage certficate lifecycles, check out [Que Cloud](addque.com) for a fully managed, cost efficient service. ß

### 2.3 Opinionated secure constructors

Use the secure defaults to get started quickly:

```rust
use que_engine::{C2paConfig, C2paVerificationConfig, AssetRef, SigAlg, Signer, EngineDefaults};

let signer: Signer = "env:CERT_PEM,KEY_PEM".parse().unwrap();
let sign_cfg = C2paConfig::secure_default(
    AssetRef::Path("/path/to/input.jpg".into()),
    signer,
    EngineDefaults::SIGNING_ALGORITHM, // Uses centralized default (Es256)
);

let verify_cfg = C2paVerificationConfig::secure_default(
    AssetRef::Path("/path/to/signed.jpg".into())
);

// All config structs have secure_default() methods that use EngineDefaults constants
let ingredient_cfg = IngredientConfig::secure_default(AssetRef::Path("/path/to/asset.jpg".into()));
```

#### Accessing Default Values Directly

You can also reference individual defaults directly:

```rust
// Check what the default signing algorithm is
let alg = EngineDefaults::SIGNING_ALGORITHM; // SigAlg::Es256

// Use in your own configuration logic
let embed_manifests = EngineDefaults::EMBED_MANIFESTS; // true
```

## 3. Next Steps

- **[API Reference](./docs/api.md):** Explore the public functions available in the engine.
- **[Data Structures](./docs/TYPES.md):** Understand the configuration and result types used by the API.

---

## 4. Production Deployment & API Best Practices

### 4.1 Memory & Security Limits

**Production-tuned limits to prevent memory exhaustion:**

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_IN_MEMORY_ASSET_SIZE` | 128MB | Prevents loading very large files into RAM |
| `MAX_IN_MEMORY_OUTPUT_SIZE` | 128MB | Prevents memory explosion from large signed assets |
| `MAX_STREAM_COPY_SIZE` | 1GB | Max size for stream-to-temp-file operations |
| `MAX_STREAM_READ_TIMEOUT_SECS` | 300 (5min) | Max time for stream operations |

**When to use each AssetRef type:**
- **AssetRef::Bytes**: Files < 128MB, API uploads, memory-resident data
- **AssetRef::Stream**: Files > 10MB, large files, memory-constrained servers
- **AssetRef::Path**: Local files, after secure URL fetching

### 4.2 Remote Asset Handling

**For remote URLs (S3, HTTP endpoints):**
1. **Validate first:** Use `validate_external_http_url()` before fetching
2. **HEAD request:** Check Content-Length and Content-Type before downloading
3. **Size limits:** Enforce < 1GB content length
4. **MIME filtering:** Only allow supported types (JPEG, PNG, MP4, PDF, etc.)
5. **Fetch to temp file:** Store as `AssetRef::Path` for processing
6. **Timeout handling:** < 5 minutes connect/read timeouts

**Security policies:**
- HTTPS only by default
- No redirects or limited redirects with re-validation
- DNS re-resolution with IP verification
- Allow only specific MIME types you support

### 4.3 Content Type Handling

**Always provide `content_type` for streams when possible:**
```rust
// Good: Explicit content type
AssetRef::Stream {
    reader: stream,
    content_type: Some("image/jpeg".to_string())
}

// Engine will attempt auto-detection if None, but explicit is better
```

### 4.4 Error Handling

**Memory limit errors:**
- `Config("in-memory asset too large")` - File exceeds 128MB
- `Config("signed output too large to return in memory")` - Output exceeds 128MB
- `Config("Stream size limit exceeded")` - Stream copy exceeds 1GB

**Handle these by:**
1. Using `AssetRef::Stream` for large inputs
2. Using `OutputTarget::Path` for large outputs
3. Implementing streaming uploads in your API

### 4.5 Supported File Formats

QueEngine only supports the file formats officially supported by C2PA. The engine will automatically detect content types for supported formats, but for best results, provide explicit `content_type` when using `AssetRef::Stream`.

**Supported formats include:**
- **Images**: JPEG, PNG, GIF, WebP, HEIC, HEIF, AVIF, TIFF, SVG
- **Video**: MP4, MOV, AVI
- **Audio**: MP3, M4A, WAV
- **Documents**: PDF (read-only)

For the complete list of supported formats and their MIME types, see [docs/TYPES.md](docs/TYPES.md).

---

## 5. CI/CD

QueEngine uses **GitHub Actions** to enforce that FFI bindings (Swift/Kotlin) are always up-to-date when a release is tagged.

### Why?
The `que-ffi` crate generates Swift and Kotlin bindings from the Rust FFI layer. If these bindings are not regenerated before a release, the published SDKs may be out of sync with the engine code. This can cause runtime errors or missing functionality.

### How It Works
- A workflow (`.github/workflows/release-check.yml`) runs **only on tag pushes** (e.g., `v1.2.0`).
- It:
  1. Builds the project in release mode.
  2. Runs the `build.sh` script to regenerate Swift/Kotlin bindings.
  3. Fails if the repository is “dirty” (i.e., if bindings changed but were not committed).

### Developer Workflow
1. Before tagging a release, always run:

   ```bash
   ./build.sh
   git add bindings/
   git commit -m "chore: update FFI bindings"
   ```

2. Tag and push the release:

   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```

3. If bindings were not updated, the CI job will fail with:

   ```
   ❌ Bindings are out of date for this release tag.
   Run ./build.sh locally, commit the changes, and re-tag the release.
   ```

This ensures that **every release ships with correct, up-to-date FFI bindings**.