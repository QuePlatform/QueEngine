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

**Example (secure defaults):**
```rust
use que_engine::{sign_c2pa, C2paConfig, AssetRef, OutputTarget, Signer, SigAlg};
use std::path::PathBuf;
use std::str::FromStr;

let signer = Signer::from_str("env:CERT_PEM,KEY_PEM").unwrap();
let mut config = C2paConfig::secure_default(
    AssetRef::Path(PathBuf::from("image.jpg")),
    signer,
    SigAlg::Es256,
);
config.output = OutputTarget::Path(PathBuf::from("signed.jpg"));

sign_c2pa(config).unwrap();
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

let mut config = C2paVerificationConfig::secure_default(AssetRef::Path(PathBuf::from("signed.jpg")));
config.mode = VerifyMode::Detailed;
// To fetch remote manifests, enable the `remote_manifests` feature and opt-in:
// config.allow_remote_manifests = true;
// To include certificate chain in results:
// config.include_certificates = Some(true);

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

---

## CAWG (Creator Assertions Working Group) Functions

The following functions are available when the `cawg` feature flag is enabled:

### `create_cawg_x509_config`
Creates a CAWG identity configuration for X.509 certificate-based identity assertions.

```rust
#[cfg(feature = "cawg")]
pub fn create_cawg_x509_config(
    signer: Signer,
    referenced_assertions: Vec<String>
) -> CawgIdentity
```

**Example:**
```rust
use que_engine::{create_cawg_x509_config, Signer, CawgIdentity};

let signer = Signer::from_str("env:CAWG_CERT_PEM,CAWG_KEY_PEM").unwrap();
let cawg_identity = create_cawg_x509_config(
    signer,
    vec!["cawg.training-mining".to_string()]
);
```

### `create_cawg_verify_options`
Creates CAWG verification options with specified validation settings.

```rust
#[cfg(feature = "cawg")]
pub fn create_cawg_verify_options(
    validate: bool,
    require_valid_identity: bool
) -> CawgVerifyOptions
```

**Example:**
```rust
use que_engine::{create_cawg_verify_options, CawgVerifyOptions};

// Enable CAWG validation and require valid identity
let cawg_opts = create_cawg_verify_options(true, true);
```
