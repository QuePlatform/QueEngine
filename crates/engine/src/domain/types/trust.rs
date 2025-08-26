/// Trust policy configuration, modeled after c2patool trust settings but
/// using raw bytes to avoid I/O in the engine.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicyConfig {
    /// PEM trust anchors data (concatenated PEMs)
    pub anchors: Option<Vec<u8>>,
    /// Allowed list of specific signing certificates (PEM)
    pub allowed_list: Option<Vec<u8>>,
    /// Allowed EKUs in OID dot notation
    pub allowed_ekus: Option<Vec<String>>,

    /// Enable trust checks for identity assertions (c2pa >= 0.59)
    pub verify_identity_trust: Option<bool>,
}
