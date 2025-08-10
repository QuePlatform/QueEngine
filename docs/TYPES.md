# Data Structures (Types)

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

## VerificationResult
The comprehensive result of a `verify_c2pa` call.
```rust
pub struct VerificationResult {
    pub report: String,
    pub certificates: Option<Vec<CertInfo>>,
    pub status: Option<Vec<ValidationStatus>>,
    pub verdict: Option<Verdict>,
}
```