#[cfg(feature = "cawg")]
use c2pa::{
    crypto::raw_signature,
    identity::{
        builder::{AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner},
        validator::CawgValidator,
        x509::AsyncX509CredentialHolder,
    },

};
use crate::domain::error::{EngineError, EngineResult};
use crate::domain::cawg::{CawgIdentity, CawgVerifyOptions, CawgVerification};

/// Creates a CAWG-enabled signer from CAWG identity configuration.
/// This creates a dual-signer setup where the main C2PA signer is wrapped
/// with CAWG identity assertion capabilities.
///
/// This function temporarily extracts raw certificate/key data to create the
/// async raw signers needed for CAWG, but immediately discards the raw data
/// after creating the signers.
///
/// # Arguments
/// * `main_signer` - The main C2PA signer (will be temporarily converted to raw form)
/// * `main_alg` - Signing algorithm for the main signer
/// * `main_timestamp` - Optional timestamp URL for the main signer
/// * `cawg_config` - CAWG identity configuration
///
/// # Returns
/// A signer that includes both C2PA signing and CAWG identity assertion
#[cfg(feature = "cawg")]
pub async fn create_cawg_signer(
    main_signer: &crate::crypto::signer::Signer,
    main_alg: c2pa::SigningAlg,
    main_timestamp: Option<String>,
    cawg_config: &CawgIdentity,
) -> EngineResult<Box<dyn c2pa::AsyncSigner>> {
    // Temporarily extract raw cert/key data for async signer creation
    // This is scoped to minimize the exposure of raw key material
    let (main_cert, main_key) = {
        match main_signer {
            crate::crypto::signer::Signer::Local { cert_path, key_path } => {
                let cert = std::fs::read(cert_path)
                    .map_err(|e| EngineError::Config(format!("Failed to read cert: {}", e)))?;
                let key = std::fs::read(key_path)
                    .map_err(|e| EngineError::Config(format!("Failed to read key: {}", e)))?;
                (cert, key)
            }
            crate::crypto::signer::Signer::Env { cert_var, key_var } => {
                let cert = std::env::var(cert_var)
                    .map_err(|_| EngineError::Config(format!("Cert env var not found: {}", cert_var)))?
                    .into_bytes();
                let key = std::env::var(key_var)
                    .map_err(|_| EngineError::Config(format!("Key env var not found: {}", key_var)))?
                    .into_bytes();
                (cert, key)
            }
        }
    };

    // Create main C2PA raw signer - raw data is consumed here and not exposed further
    let main_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
        &main_cert,
        &main_key,
        main_alg,
        main_timestamp,
    )
    .map_err(|e| EngineError::C2pa(c2pa::Error::OtherError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))))?;

    // Create CAWG raw signer from the CAWG identity configuration
    let cawg_raw_signer = create_cawg_raw_signer(cawg_config).await?;

    // Wrap the main signer with CAWG identity assertion signer
    let mut ia_signer = AsyncIdentityAssertionSigner::new(main_raw_signer);

    // Create X.509 credential holder for CAWG
    let x509_holder = AsyncX509CredentialHolder::from_async_raw_signer(cawg_raw_signer);

    // Create identity assertion builder
    let mut iab = AsyncIdentityAssertionBuilder::for_credential_holder(x509_holder);

    // Convert Vec<String> to Vec<&str> for the API
    let referenced_assertions: Vec<&str> = cawg_config.referenced_assertions.iter().map(|s| s.as_str()).collect();
    iab.add_referenced_assertions(&referenced_assertions);

    // Add the identity assertion to the signer
    ia_signer.add_identity_assertion(iab);

    Ok(Box::new(ia_signer))
}

/// Creates a CAWG raw signer from CAWG identity configuration.
/// This helper function converts the QueEngine Signer abstraction into
/// a c2pa raw signer for CAWG identity assertions.
#[cfg(feature = "cawg")]
async fn create_cawg_raw_signer(cfg: &CawgIdentity) -> EngineResult<Box<dyn c2pa::crypto::raw_signature::AsyncRawSigner + Send + Sync>> {
    use crate::crypto::signer::Signer;
    match &cfg.signer {
        Signer::Local { cert_path, key_path } => {
            let cert_bytes = std::fs::read(cert_path)
                .map_err(|e| EngineError::Config(format!("Failed to read CAWG cert: {}", e)))?;
            let key_bytes = std::fs::read(key_path)
                .map_err(|e| EngineError::Config(format!("Failed to read CAWG key: {}", e)))?;

            raw_signature::async_signer_from_cert_chain_and_private_key(
                &cert_bytes,
                &key_bytes,
                cfg.signing_alg.to_c2pa(),
                cfg.timestamper.as_ref().and_then(|t| t.resolve()),
            )
            .map_err(|e| EngineError::C2pa(c2pa::Error::OtherError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))))
        }
        Signer::Env { cert_var, key_var } => {
            let cert_pem = std::env::var(cert_var)
                .map_err(|_| EngineError::Config(format!("CAWG cert env var not found: {}", cert_var)))?;
            let key_pem = std::env::var(key_var)
                .map_err(|_| EngineError::Config(format!("CAWG key env var not found: {}", key_var)))?;

            raw_signature::async_signer_from_cert_chain_and_private_key(
                cert_pem.as_bytes(),
                key_pem.as_bytes(),
                cfg.signing_alg.to_c2pa(),
                cfg.timestamper.as_ref().and_then(|t| t.resolve()),
            )
            .map_err(|e| EngineError::C2pa(c2pa::Error::OtherError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))))
        }
    }
}

/// Extracts signature information from CAWG identity assertions.
/// Parses the CAWG identity assertion to extract signature metadata.
#[cfg(feature = "cawg")]
fn extract_cawg_signature_info(reader: &c2pa::Reader) -> Option<serde_json::Value> {
    if let Some(active_manifest) = reader.active_manifest() {
        for assertion in active_manifest.assertions() {
            if assertion.label() == "cawg.identity" {
                if let Ok(assertion_data) = assertion.to_assertion::<serde_json::Value>() {
                    return Some(assertion_data);
                }
            }
        }
    }
    None
}

/// Validates CAWG identity assertions in a C2PA reader.
/// Runs the CAWG validator and extracts identity assertion information.
///
/// # Arguments
/// * `reader` - The C2PA reader containing the manifest to validate
/// * `_opts` - CAWG verification options controlling validation behavior (unused for now)
///
/// # Returns
/// CAWG verification results including presence, validity, and signature info
#[cfg(feature = "cawg")]
pub async fn validate_cawg(
    reader: &mut c2pa::Reader,
    _opts: &CawgVerifyOptions,
) -> EngineResult<CawgVerification> {
    // Run CAWG validation
    reader
        .post_validate_async(&CawgValidator {})
        .await
        .map_err(|e| EngineError::C2pa(c2pa::Error::OtherError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))))?;

    // Check if CAWG identity assertion is present and extract information
    let validation_results = reader
        .validation_results()
        .ok_or_else(|| EngineError::Config("No validation results available".into()))?;

    let mut cawg_present = false;
    let mut cawg_valid = true;

    // Check for CAWG identity assertions in validation results
    if let Some(active_manifest) = validation_results.active_manifest() {
        for status in active_manifest.success() {
            if status.code().starts_with("cawg.identity") {
                cawg_present = true;
                break;
            }
        }

        // Check for CAWG validation failures
        for status in active_manifest.failure() {
            if status.code().starts_with("cawg.identity") {
                cawg_present = true;
                cawg_valid = false;
                break;
            }
        }
    }

    // Extract signature information from CAWG identity assertion if present
    let signature_info = if cawg_present {
        extract_cawg_signature_info(reader)
    } else {
        None
    };

    Ok(CawgVerification {
        present: cawg_present,
        valid: cawg_valid,
        signature_info,
    })
}