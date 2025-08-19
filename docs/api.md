# API Reference

This document details the public functions exposed by the `que-engine` crate.

## Error Handling

All public functions return an `EngineResult<T>`, which is an alias for:
```rust
Result<T, EngineError>
```

### EngineError
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

---

## Core Functions

### `sign_c2pa`
Signs a digital asset with a C2PA manifest.

```rust
pub fn sign_c2pa(cfg: C2paConfig) -> EngineResult<Option<Vec<u8>>>
```

**Example:**
```rust
use que_engine::{sign_c2pa, C2paConfig, AssetRef, OutputTarget, Signer, SigAlg};
use std::path::PathBuf;
use std::str::FromStr;

let config = C2paConfig {
    source: AssetRef::Path(PathBuf::from("image.jpg")),
    output: OutputTarget::Path(PathBuf::from("signed.jpg")),
    manifest_definition: Some(r#"{"title": "My Test Image"}"#.to_string()),
    signer: Signer::from_str("local:cert.pem,key.pem").unwrap(),
    signing_alg: SigAlg::Ps256,
    embed: true,
    parent: None,
    parent_base_dir: None,
    timestamper: None,
    remote_manifest_url: None,
    trust_policy: None, 
    skip_post_sign_validation: false,
};

sign_c2pa(config).unwrap();
```

**Example with built-in test signer:**
```rust
let config = C2paConfig {
    source: AssetRef::Path(PathBuf::from("image.jpg")),
    output: OutputTarget::Path(PathBuf::from("signed.jpg")),
    manifest_definition: Some(r#"{"title": "My Test Image"}"#.to_string()),
    signer: Signer::from_str("builtin:es256").unwrap(), // Uses bundled test certificates
    signing_alg: SigAlg::Es256, // Must match the built-in signer algorithm
    embed: true,
    parent: None,
    parent_base_dir: None,
    timestamper: None,
    remote_manifest_url: None,
    trust_policy: None,
    skip_post_sign_validation: false,
};
```

---

### `verify_c2pa`
Verifies the C2PA provenance of a digital asset.

```rust
pub fn verify_c2pa(cfg: C2paVerificationConfig) -> EngineResult<VerificationResult>
```

**Example:**
```rust
use que_engine::{verify_c2pa, C2paVerificationConfig, AssetRef, VerifyMode, TrustPolicyConfig};
use std::path::PathBuf;

let config = C2paVerificationConfig {
    source: AssetRef::Path(PathBuf::from("signed.jpg")),
    mode: VerifyMode::Detailed,
    allow_remote_manifests: true,
    policy: Some(TrustPolicyConfig::default()),
};

let result = verify_c2pa(config).unwrap();
println!("{}", result.report);
```

---

### `create_ingredient`
Creates a C2PA Ingredient from an asset.

```rust
pub fn create_ingredient(cfg: IngredientConfig) -> EngineResult<Option<Vec<u8>>>
```

---

### `generate_fragmented_bmff`
Signs fragmented BMFF content (e.g., fMP4 video).

```rust
#[cfg(all(feature = "c2pa", feature = "bmff"))]
pub fn generate_fragmented_bmff(cfg: FragmentedBmffConfig) -> EngineResult<()>
```
