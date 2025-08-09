// crates/engine/src/domain/types.rs

use std::path::PathBuf;

/// Supported signature algorithms for the engine. Mapped to c2pa internally.
#[derive(Debug, Clone, Copy)]
pub enum SigAlg {
    Es256,
    Es384,
    Ps256,
    Ed25519,
}

impl SigAlg {
    #[cfg(feature = "c2pa")]
    pub fn to_c2pa(self) -> c2pa::SigningAlg {
        match self {
            SigAlg::Es256 => c2pa::SigningAlg::Es256,
            SigAlg::Es384 => c2pa::SigningAlg::Es384,
            SigAlg::Ps256 => c2pa::SigningAlg::Ps256,
            SigAlg::Ed25519 => c2pa::SigningAlg::Ed25519,
        }
    }
}

/// Where verification output should be focused.
#[derive(Debug, Clone, Copy)]
pub enum VerifyMode {
    Summary,
    Info,
    Detailed,
    Tree,
}

/// A reference to an asset, which can be either a path or in-memory bytes.
#[derive(Debug, Clone)]
pub enum AssetRef {
    Path(PathBuf),
    Bytes(Vec<u8>), // Use an owned Vec<u8> to avoid lifetimes
}

/// A target for the output of a generation operation.
#[derive(Debug, Clone)]
pub enum OutputTarget {
    Path(PathBuf),
    Memory, // return Vec<u8> from adapter
}

/// Configuration for C2PA generation.
#[derive(Debug, Clone)]
pub struct C2paConfig {
    pub source: AssetRef,
    pub output: OutputTarget,
    pub manifest_definition: Option<String>,
    pub parent_path: Option<PathBuf>,
    pub signer: crate::crypto::signer::Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<crate::crypto::timestamper::Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
}

/// Configuration for C2PA verification.
#[derive(Debug, Clone)]
pub struct C2paVerificationConfig {
    pub source_path: PathBuf,
    pub mode: VerifyMode,
}