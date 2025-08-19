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
```rust
pub enum AssetRef {
    Path(PathBuf),
    Bytes {
        data: Vec<u8>,
        ext: Option<String>,
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
}
```

## Signer
Specifies the source of the cryptographic key and certificate.
```rust
pub enum Signer {
    Local { cert_path: PathBuf, key_path: PathBuf },
    Env { cert_var: String, key_var: String },
    /// Built-in ES256 test signer that uses engine-bundled PEMs.
    /// Note: This uses test certificates and should be replaced with real certificates in production.
    BuiltinEs256,
}
```

### Built-in Test Signer

The `BuiltinEs256` signer variant uses test certificates bundled with the engine:
- `crates/engine/es256_certs.pem` - Test certificate chain
- `crates/engine/es256_private.key` - Test private key

**Important:** These are test certificates and should not be used in production. In the future, this will need to be replaced with real, properly signed certificates that meet production security requirements.

## Timestamper
Specifies the RFC 3161 Timestamp Authority (TSA) to use.
```rust
pub enum Timestamper {
    Digicert,
    Custom(String),
}
```