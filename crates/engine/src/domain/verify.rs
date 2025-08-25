// crates/engine/src/domain/verify.rs
use serde::Serialize;

/// Certificate summary extracted from the active claim signature.
#[derive(Debug, Serialize, Clone, Default)]
pub struct CertInfo {
    pub alg: Option<String>,
    pub issuer: Option<String>,
    pub cert_serial_number: Option<String>,
    pub time: Option<String>,
    pub revocation_status: Option<bool>,
    /// The full certificate chain in PEM format.
    pub chain_pem: Option<String>,
}

/// Generic verification result. For now, a string report like c2pa::Reader
/// produces; can be made more structured later.
#[derive(Debug, Serialize, Clone)]
pub struct VerificationResult {
    pub report: String,
    /// Optional list of certificates involved in signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<CertInfo>>,
    /// Structured validation statuses mapped from c2pa validation results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<ValidationStatus>>,   
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,

    /// Whether the manifest is embedded in the asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_embedded: Option<bool>,

    /// The remote manifest URL, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,

}

/// Structured validation status entry.
#[derive(Debug, Serialize, Clone)]
pub struct ValidationStatus {
    pub code: String,
    pub url: Option<String>,
    pub explanation: Option<String>,
    pub ingredient_uri: Option<String>,
    pub passed: bool,
}

#[derive(Debug, Serialize, Clone)]
pub enum Verdict {
    Allowed,
    Warning,
    Rejected,
}
