use serde::{Deserialize, Serialize};
use crate::crypto::signer::Signer;
use crate::crypto::timestamper::Timestamper;
use crate::SigAlg;

/// CAWG X.509 identity configuration for signing.
/// This defines the identity assertion that will be added to the C2PA manifest.
#[cfg(feature = "cawg")]
#[derive(Debug, Clone)]
pub struct CawgIdentity {
    /// BYO certificate and private key for the CAWG identity signer
    pub signer: Signer,
    /// Signing algorithm for the CAWG identity (default: Ed25519)
    pub signing_alg: SigAlg,
    /// List of assertion labels that this identity assertion should reference
    pub referenced_assertions: Vec<String>,
    /// Optional timestamp authority for the CAWG identity signature
    pub timestamper: Option<Timestamper>,
}

/// Options for CAWG identity verification.
/// Controls whether CAWG validation should be performed and how failures are handled.
#[cfg(feature = "cawg")]
#[derive(Debug, Clone)]
pub struct CawgVerifyOptions {
    /// Whether to run CAWG identity validation
    pub validate: bool,
    /// Whether to fail verification if CAWG identity is missing or invalid
    pub require_valid_identity: bool,
}

/// Result of CAWG identity verification.
/// Contains information about whether a CAWG identity assertion was present
/// and whether it was successfully validated.
#[cfg(feature = "cawg")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgVerification {
    /// Whether a CAWG identity assertion was present in the manifest
    pub present: bool,
    /// Whether the CAWG identity assertion was successfully validated
    pub valid: bool,
    /// Signature information extracted from the CAWG identity assertion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_info: Option<serde_json::Value>,
}
