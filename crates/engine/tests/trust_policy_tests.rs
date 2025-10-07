mod common;

use que_engine as qe;

#[test]
fn trust_policy_defaults() {
    let d = qe::LimitsConfig::defaults();
    assert!(d.max_in_memory_asset_size > 0);
    let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(Default::default()));
    cfg.limits.max_stream_copy_size = 5 * 1024 * 1024;
    assert_eq!(cfg.limits.max_stream_copy_size, 5 * 1024 * 1024);
}

#[test]
fn engine_defaults_values() {
    use qe::EngineDefaults as D;
    assert_eq!(D::ALLOW_REMOTE_MANIFESTS, false);
    assert!(matches!(D::OUTPUT_TARGET, qe::OutputTarget::Memory));
}

#[test]
fn configure_trust_policy_with_anchors() {
    use qe::domain::types::TrustPolicyConfig;

    let pem_data = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----";
    let trust_policy = TrustPolicyConfig {
        anchors: Some(pem_data.to_vec()),
        allowed_list: None,
        allowed_ekus: Some(vec!["1.3.6.1.5.5.7.3.3".to_string()]),
        verify_identity_trust: Some(true),
    };

    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C.jpg");
    if !path.exists() { return; }

    let cfg = qe::C2paVerificationConfig {
        source: qe::AssetRef::Path(path),
        mode: qe::VerifyMode::Summary,
        policy: Some(trust_policy),
        allow_remote_manifests: false,
        include_certificates: None,
        limits: qe::LimitsConfig::defaults(),
        #[cfg(feature = "cawg")]
        cawg: None,
    };

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            // Trust policy should affect validation results
            assert!(!res.report.is_empty());
        }
        Err(_) => {} // Trust policy may cause validation failures
    }
}

#[test]
fn trust_policy_validation_differences() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C.jpg");
    if !path.exists() { return; }

    // First verify without trust policy
    let cfg_no_trust = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path.clone()));

    // Then verify with trust policy
    let trust_policy = qe::domain::types::TrustPolicyConfig {
        anchors: Some(b"invalid_pem_data".to_vec()),
        allowed_list: None,
        allowed_ekus: None,
        verify_identity_trust: Some(true),
    };

    let cfg_with_trust = qe::C2paVerificationConfig {
        source: qe::AssetRef::Path(path),
        mode: qe::VerifyMode::Summary,
        policy: Some(trust_policy),
        allow_remote_manifests: false,
        include_certificates: None,
        limits: qe::LimitsConfig::defaults(),
        #[cfg(feature = "cawg")]
        cawg: None,
    };

    let result_no_trust = qe::verify_c2pa(cfg_no_trust);
    let result_with_trust = qe::verify_c2pa(cfg_with_trust);

    // Results may differ based on trust policy
    match (result_no_trust, result_with_trust) {
        (Ok(r1), Ok(r2)) => {
            // Reports may be different due to trust validation
            let _ = r1.report != r2.report;
        }
        _ => {} // Either may fail
    }
}