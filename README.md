# QueEngine

## 1. Overview

**QueEngine** is a high-level, configurable Rust library designed to be the core provenance and authenticity engine for the Que Platform. Its primary function is to provide a safe, robust, and developer-friendly interface for interacting with the C2PA (Coalition for Content Provenance and Authenticity) standard.

While the official `c2pa-rs` library is powerful, it is a low-level toolkit. QueEngine acts as an abstraction layer on top of it, providing:

- **Safe Defaults:** Common operations like signing and verifying work out-of-the-box with secure, opinionated defaults.
- **Powerful Configuration:** Exposes the full power of the underlying C2PA library through well-structured configuration objects, allowing advanced users to customize every aspect of the process.
- **Clear Boundaries:** A clean separation between pure domain logic and concrete implementation details (the "adapter" pattern).
- **Security & Stability:** Manages thread-safety for global settings and provides robust error handling to prevent panics from crossing FFI boundaries.

### 1.1. Role in the Que Ecosystem

- **QueCloud:** The managed service (`QueCloud`) uses QueEngine as a dependency to perform all its C2PA operations (signing with cloud-managed keys, verification with managed trust policies).
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

#### Feature Gating

QueEngine is heavily feature-gated to produce minimal binaries for different targets. This is critical for security and performance. For example, the `enclave` feature (for on-device signing) should never be compiled into the `QueCloud` server binary, and the `kms` feature (for cloud signing) should never be compiled into a device-side library.

See the **Feature Flags** section for a complete list.

## 2. Getting Started

Add QueEngine to your project's `Cargo.toml`.

Currently, we have not figured out a way to import the github repository QueEngine because it is private. QueCloud references the repository directly since it is on the same machine

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

### 2.3 Opinionated secure constructors

Use the secure defaults to get started quickly:

```rust
use que_engine::{C2paConfig, C2paVerificationConfig, AssetRef, SigAlg, Signer};

let signer: Signer = "env:CERT_PEM,KEY_PEM".parse().unwrap();
let sign_cfg = C2paConfig::secure_default(
    AssetRef::Path("/path/to/input.jpg".into()),
    signer,
    SigAlg::Es256,
);

let verify_cfg = C2paVerificationConfig::secure_default(
    AssetRef::Path("/path/to/signed.jpg".into())
);
```

## 3. Next Steps

- **[API Reference](./docs/api.md):** Explore the public functions available in the engine.
- **[Data Structures](./docs/TYPES.md):** Understand the configuration and result types used by the API.

---

## 4. CI/CD

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

---

## 5. Notes on network behavior and opt-ins

- Remote manifests: disabled by default. To enable, compile with the `remote_manifests` feature and set `C2paVerificationConfig.allow_remote_manifests = true`.
- HTTP URLs: disallowed by default. To enable, compile with the `http_urls` feature and set `C2paConfig.allow_insecure_remote_http = Some(true)` (or the same on `FragmentedBmffConfig`).
- The engine validates URLs and blocks private/loopback/link-local IPs even when specified as hostnames.