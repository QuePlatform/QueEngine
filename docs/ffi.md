# FFI Notes (Swift/Kotlin/WASM)

- FFI bindings are generated in `crates/ffi` and emitted to `/bindings` by CI.
- The FFI surface fully mirrors the Rust API, providing typed configurations and structured results.
- Bindings are generated using UniFFI with proper export attributes and error handling.

## Current Status

✅ **Swift & Kotlin**: Fully working with complete API coverage
⚠️ **WASM**: Configured but blocked by OpenSSL dependencies (see below)

## FFI API Surface

### Core Functions (mirroring Rust API)

- `sign_c2pa_ffi(cfg: FfiC2paConfig)` - Sign digital assets with C2PA manifests
- `verify_c2pa_ffi(cfg: FfiC2paVerificationConfig)` - Verify C2PA signatures and return structured results
- `create_ingredient_ffi(cfg: FfiIngredientConfig)` - Create C2PA ingredients from assets
- `generate_fragmented_bmff_ffi(cfg: FfiFragmentedBmffConfig)` - Sign fragmented BMFF content (requires `bmff` feature)

### Configuration Types

- `FfiC2paConfig` - Complete signing configuration with asset references, signer URIs, trust policies, and limits
- `FfiC2paVerificationConfig` - Verification configuration with mode selection and limits
- `FfiIngredientConfig` - Ingredient creation configuration
- `FfiFragmentedBmffConfig` - Fragmented BMFF signing configuration

### Core Types

- `FfiAssetRef` - Asset references (Path or Bytes)
- `FfiOutputTarget` - Output destinations (Path or Memory)
- `FfiSigAlg` - Signature algorithms (Es256, Es384, Ps256, Ed25519)
- `FfiVerifyMode` - Verification modes (Summary, Info, Detailed, Tree)
- `FfiLimitsConfig` - Per-call memory/stream limits (max sizes and timeouts)

### Result Types

- `FfiVerificationResult` - Structured verification results with certificates, status, and verdict
- `FfiCertInfo` - Certificate information
- `FfiValidationStatus` - Individual validation status entries
- `FfiVerdict` - Overall verification verdict (Allowed, Warning, Rejected)

### Legacy Functions (deprecated)

- `sign_file_c2pa()` - Simple file-based signing (use `sign_c2pa_ffi` instead)
- `verify_file_c2pa()` - Simple file verification (use `verify_c2pa_ffi` instead)
- `VerifyOptions` - Legacy verification options struct

### Error Handling

- `FfiError` - Error enum for all FFI operations
- Panics are caught and mapped to error codes/messages before crossing the FFI boundary

## Feature Flags

Enable features on the FFI crate to access additional functionality:

```toml
[dependencies]
que-engine-ffi = { version = "0.1", features = ["bmff", "cawg", "remote_manifests"] }
```

Available features:
- `c2pa` (default) - Core C2PA functionality
- `bmff` - Fragmented BMFF support
- `cawg` - CAWG identity assertions
- `remote_manifests` - Remote manifest fetching
- `http_urls` - HTTP URL support (insecure)

## Security and Configuration

- **Memory Limits**: Configurable per-call limits via `FfiLimitsConfig` prevent memory exhaustion
- **BYO Certificates**: No bundled certificates - provide your own via file paths or environment variables
- **Secure Defaults**: HTTPS-only, no remote manifests, restrictive limits
- **URL Validation**: DNS/IP checks block private/loopback/link-local ranges
- **Feature Gating**: Security-critical features must be explicitly enabled

## Usage Examples

### Swift
```swift
let config = FfiC2paConfig(
    source: FfiAssetRef.Path("/path/to/image.jpg"),
    output: FfiOutputTarget.Path("/path/to/signed.jpg"),
    manifestDefinition: nil,
    parent: nil,
    parentBaseDir: nil,
    signerUri: "env:CERT_PEM,KEY_PEM",
    signingAlg: FfiSigAlg.Es256,
    timestamper: nil,
    remoteManifestUrl: nil,
    embed: true,
    trustPolicy: nil,
    skipPostSignValidation: false,
    allowInsecureRemoteHttp: nil,
    limits: FfiLimitsConfig.defaults()
)

let result = try QueEngine.signC2paFfi(config: config)
```

### Kotlin
```kotlin
val config = FfiC2paConfig(
    source = FfiAssetRef.Path("/path/to/image.jpg"),
    output = FfiOutputTarget.Path("/path/to/signed.jpg"),
    manifestDefinition = null,
    parent = null,
    parentBaseDir = null,
    signerUri = "env:CERT_PEM,KEY_PEM",
    signingAlg = FfiSigAlg.ES256,
    timestamper = null,
    remoteManifestUrl = null,
    embed = true,
    trustPolicy = null,
    skipPostSignValidation = false,
    allowInsecureRemoteHttp = null,
    limits = FfiLimitsConfig.defaults()
)

val result = QueEngine.signC2paFfi(config)
```

## WASM Support

**Current Status**: ⚠️ **Not Available** - Blocked by OpenSSL dependencies

The FFI crate is fully configured for WASM generation, but WASM bindings cannot be built due to the underlying `c2pa` crate's dependency on OpenSSL, which doesn't compile to WASM targets.
