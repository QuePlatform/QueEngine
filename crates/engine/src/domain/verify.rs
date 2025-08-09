use serde::Serialize;

/// Generic verification result. For now, a string report like c2pa::Reader
/// produces; can be made more structured later.
#[derive(Debug, Serialize, Clone)]
pub struct VerificationResult {
    pub report: String,
}