//! Signer abstraction for the engine.
//! Today supports local files or env variables (dev). KMS/HSM/Enclave come next.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Invalid signer URI scheme: expected 'local:' or 'env:'")]
    InvalidScheme,
    #[error("Missing path for 'local:' signer")]
    MissingLocalPath,
    #[error("Missing variable name for 'env:' signer")]
    MissingEnvVar,
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
}

/// Source for a cryptographic keypair.
/// Format examples:
/// - local:/path/to/cert.pem,/path/to/private.pem
/// - env:CERT_VAR,KEY_VAR
#[derive(Debug, Clone)]
pub enum Signer {
    Local { cert_path: PathBuf, key_path: PathBuf },
    Env { cert_var: String, key_var: String },
}

impl FromStr for Signer {
    type Err = SignerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, value) = s.split_once(':').ok_or(SignerError::InvalidScheme)?;
        let parts: Vec<&str> = value.split(',').collect();
        if parts.len() != 2 {
            return Err(SignerError::InvalidScheme);
        }

        match scheme {
            "local" => Ok(Signer::Local {
                cert_path: PathBuf::from(parts[0]),
                key_path: PathBuf::from(parts[1]),
            }),
            "env" => Ok(Signer::Env {
                cert_var: parts[0].to_string(),
                key_var: parts[1].to_string(),
            }),
            _ => Err(SignerError::InvalidScheme),
        }
    }
}

impl Signer {
    /// Resolve into a c2pa signer (only available with the c2pa feature).
    #[cfg(feature = "c2pa")]
    pub fn resolve(
        &self,
        alg: c2pa::SigningAlg,
    ) -> Result<Box<dyn c2pa::Signer>> {
        match self {
            Signer::Local {
                cert_path,
                key_path,
            } => {
                let signer = c2pa::create_signer::from_files(
                    cert_path,
                    key_path,
                    alg,
                    None,
                )
                .context("Failed to create signer from local files")?;
                Ok(signer)
            }
            Signer::Env { cert_var, key_var } => {
                let cert_pem = std::env::var(cert_var).map_err(|_| {
                    SignerError::EnvVarNotFound(cert_var.clone())
                })?;
                let key_pem = std::env::var(key_var).map_err(|_| {
                    SignerError::EnvVarNotFound(key_var.clone())
                })?;

                let signer = c2pa::create_signer::from_keys(
                    cert_pem.as_bytes(),
                    key_pem.as_bytes(),
                    alg,
                    None,
                )
                .context("Failed to create signer from environment variables")?;
                Ok(signer)
            }
        }
    }
}