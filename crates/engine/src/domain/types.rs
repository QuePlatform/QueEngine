// crates/engine/src/domain/types.rs

use std::path::PathBuf;

use crate::crypto::{signer::Signer, timestamper::Timestamper};

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

/// Configuration for C2PA generation (kept explicit for clarity).
#[derive(Debug, Clone)]
pub struct C2paConfig {
    pub source_path: PathBuf,
    pub dest_path: PathBuf,
    pub manifest_definition: Option<String>,
    pub parent_path: Option<PathBuf>,
    pub signer: Signer,
    pub signing_alg: SigAlg,
    pub timestamper: Option<Timestamper>,
    pub remote_manifest_url: Option<String>,
    pub embed: bool,
}

/// Configuration for C2PA verification.
#[derive(Debug, Clone)]
pub struct C2paVerificationConfig {
    pub source_path: PathBuf,
    pub mode: VerifyMode,
}