# Getting Started

Install
- Rust 1.74+
- OpenSSL headers (required by the c2pa crate when the `openssl` feature is enabled)
- Enable the `c2pa` feature (default)

Cargo
- Add to your Cargo.toml:
  - que-engine = { git = "https://github.com/QuePlatform/QueEngine", tag = "v0.2.0" }

Minimal example (sign → verify)
```rust
use que_engine::{
  sign_c2pa, verify_c2pa, AssetRef, OutputTarget, C2paConfig, C2paVerificationConfig,
  SigAlg, Signer, VerifyMode,
};
use std::str::FromStr;

let cfg = C2paConfig {
  source: AssetRef::Path("in.png".into()),
  output: OutputTarget::Path("out.png".into()),
  manifest_definition: None,
  parent: None,
  parent_base_dir: None,
  signer: Signer::from_str("local:/path/cert.pem,/path/key.pem")?,
  signing_alg: SigAlg::Es256,
  timestamper: None,
  remote_manifest_url: None,
  embed: true,
  skip_post_sign_validation: false,
};
sign_c2pa(cfg)?;

let report = verify_c2pa(C2paVerificationConfig {
  source: AssetRef::Path("out.png".into()),
  mode: VerifyMode::Summary,
  policy: None,
  allow_remote_manifests: false,
})?;
println!("{}", report.report);
```