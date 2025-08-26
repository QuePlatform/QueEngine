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

/// A target for the output of a generation operation.
#[derive(Debug, Clone)]
pub enum OutputTarget {
    Path(std::path::PathBuf),
    Memory,
}
