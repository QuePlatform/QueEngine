# Data Structures (Types)

## SigAlg
Supported signature algorithms for the engine. Mapped to c2pa internally.
```rust
pub enum SigAlg {
    Es256,
    Es384,
    Ps256,
    Ed25519,
}
```

## VerifyMode
Where verification output should be focused.
```rust
pub enum VerifyMode {
    Summary,
    Info,
    Detailed,
    Tree,
}
```

## AssetRef
Represents a reference to a digital asset.

## Memory Considerations
- `Path`: Best for local file operations. No memory overhead.
- `Bytes`: Suitable for small files (< 128MB) or when you need the entire file in memory.
- `Stream`: Recommended for large files or API scenarios to avoid memory pressure. The stream must implement `Read + Seek + Send` (or just `Read + Seek` on WASM targets).

## Supported File Formats
QueEngine only supports the file formats officially supported by C2PA:

| Extensions    | MIME type                                                                     |
| ------------- | ----------------------------------------------------------------------------- |
| `avi`         | `video/msvideo`, `video/x-msvideo`, `video/avi`, `application/x-troff-msvideo`|
| `avif`        | `image/avif`                                                                  |
| `c2pa`        | `application/x-c2pa-manifest-store`                                           |
| `dng`         | `image/x-adobe-dng`                                                           |
| `gif`         | `image/gif`                                                                   |
| `heic`        | `image/heic`                                                                  |
| `heif`        | `image/heif`                                                                  |
| `jpg`, `jpeg` | `image/jpeg`                                                                  |
| `m4a`         | `audio/mp4`                                                                   |
| `mp3`         | `audio/mpeg`                                                                  |
| `mp4`         | `video/mp4`, `application/mp4` <sup>*</sup>                                   |
| `mov`         | `video/quicktime`                                                             |
| `pdf`         | `application/pdf` <sup>**</sup>                                               |
| `png`         | `image/png`                                                                   |
| `svg`         | `image/svg+xml`                                                               |
| `tif`,`tiff`  | `image/tiff`                                                                  |
| `wav`         | `audio/wav`                                                                   |
| `webp`        | `image/webp`                                                                  |

<sup>*</sup> Fragmented MP4 (DASH) is supported only for file-based operations from the Rust library.
<br/>
<sup>**</sup> Read-only

```rust
pub enum AssetRef {
    Path(PathBuf),
    Bytes {
        data: Vec<u8>,
    },
    Stream {
        /// The streaming reader. Must implement Read + Seek + Send (or Read + Seek on WASM)
        /// Wrapped in RefCell for interior mutability
        reader: RefCell<Box<dyn CAIRead>>,
        /// Optional MIME type hint (e.g., "image/jpeg", "video/mp4")
        /// If None, the engine will attempt to detect from stream content
        content_type: Option<String>,
    },
}
```

## OutputTarget
Specifies the destination for a generation operation.
```rust
pub enum OutputTarget {
    Path(PathBuf),
    Memory,
}
```

## C2paConfig
Configuration for a standard signing operation.
```rust
pub struct C2paConfig {
    pub source: AssetRef,
    pub output: OutputTarget,
    pub manifest_definition: Option<String>,
    pub parent: Option<AssetRef>,
    pub parent_base_dir: Option<PathBuf>,
    pub signer: Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    pub trust_policy: Option<TrustPolicyConfig>,
    pub skip_post_sign_validation: bool,
    /// Opt-in: allow insecure HTTP for remote manifest URL (requires feature)
    pub allow_insecure_remote_http: Option<bool>,
    #[cfg(feature = "cawg")]
    pub cawg_identity: Option<CawgIdentity>,
}
```

## CawgIdentity
Configuration for CAWG (Creator Assertions Working Group) X.509 identity assertions during signing.
Requires the `cawg` feature flag to be enabled.
```rust
#[cfg(feature = "cawg")]
pub struct CawgIdentity {
    pub signer: Signer,
    pub signing_alg: SigAlg,
    pub referenced_assertions: Vec<String>,
    pub timestamper: Option<Timestamper>,
}
```

## C2paVerificationConfig
Configuration for a verification operation.
```rust
pub struct C2paVerificationConfig {
    pub source: AssetRef,
    pub mode: VerifyMode,
    pub policy: Option<TrustPolicyConfig>,
    pub allow_remote_manifests: bool,
    /// Opt-in: include signing certificates in result
    pub include_certificates: Option<bool>,
    #[cfg(feature = "cawg")]
    pub cawg: Option<CawgVerifyOptions>,
}
```

## CawgVerifyOptions
Configuration for CAWG identity assertion validation during verification.
Requires the `cawg` feature flag to be enabled.
```rust
#[cfg(feature = "cawg")]
pub struct CawgVerifyOptions {
    pub validate: bool,
    pub require_valid_identity: bool,
}
```

## CawgVerification
Results of CAWG identity assertion validation.
Requires the `cawg` feature flag to be enabled.
```rust
#[cfg(feature = "cawg")]
pub struct CawgVerification {
    pub present: bool,
    pub valid: bool,
    pub signature_info: Option<serde_json::Value>,
}
```

## VerificationResult
Result of a C2PA verification operation, containing the validation report and optional structured data.
```rust
pub struct VerificationResult {
    pub report: String,
    /// Optional list of certificates involved in signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<CertInfo>>,
    /// Structured validation statuses mapped from c2pa validation results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<ValidationStatus>>,
    /// Overall verification verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// Whether the manifest is embedded in the asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_embedded: Option<bool>,
    /// The remote manifest URL, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    /// CAWG identity verification results (requires feature)
    #[cfg(feature = "cawg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cawg: Option<CawgVerification>,
}
```

## TrustPolicyConfig
Defines a cryptographic trust policy for verification.
```rust
pub struct TrustPolicyConfig {
    pub anchors: Option<Vec<u8>>,
    pub allowed_list: Option<Vec<u8>>,
    pub allowed_ekus: Option<Vec<String>>,
}
```

## IngredientConfig
Configuration for building an Ingredient from an asset.
```rust
pub struct IngredientConfig {
    pub source: AssetRef,
    pub output: OutputTarget,
}
```

## FragmentedBmffConfig
Configuration for generating a manifest into fragmented BMFF content.
```rust
pub struct FragmentedBmffConfig {
    pub init_glob: PathBuf,
    pub fragments_glob: PathBuf,
    pub output_dir: PathBuf,
    pub manifest_definition: Option<String>,
    pub signer: Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
    pub skip_post_sign_validation: bool,
    /// Opt-in: allow insecure HTTP for remote manifest URL (requires feature)
    pub allow_insecure_remote_http: Option<bool>,
}
```

## Signer
Specifies the source of the cryptographic key and certificate.
```rust
pub enum Signer {
    Local { cert_path: PathBuf, key_path: PathBuf },
    Env { cert_var: String, key_var: String },
}
```

## Timestamper
Specifies the RFC 3161 Timestamp Authority (TSA) to use.
```rust
pub enum Timestamper {
    Digicert,
    Custom(String),
}
```

## EngineError
Represents errors that can occur during engine operations.
```rust
pub enum EngineError {
    Config(String),
    Io(#[from] std::io::Error),
    Json(#[from] serde_json::Error),
    Glob(#[from] glob::PatternError),
    C2pa(#[from] c2pa::Error),
    Feature(&'static str),
    VerificationFailed,
    Panic(String),
}
```

## EngineResult
Type alias for results returned by engine functions.
```rust
pub type EngineResult<T> = Result<T, EngineError>;
```