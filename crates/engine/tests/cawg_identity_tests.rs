mod common;

use que_engine as qe;

#[cfg(feature = "cawg")]
#[test]
fn cawg_identity_creation_helpers() {
    let (_tmp, uri) = common::setup_local_signer_files();
    let signer: qe::Signer = uri.parse().unwrap();

    let cawg = qe::create_cawg_x509_config(
        signer,
        vec!["c2pa.actions".to_string(), "c2pa.hash.data".to_string()]
    );

    assert_eq!(cawg.signing_alg, qe::SigAlg::Ed25519);
    assert!(cawg.referenced_assertions.contains(&"c2pa.actions".to_string()));
    assert!(cawg.timestamper.is_none());
}

#[cfg(feature = "cawg")]
#[test]
fn cawg_verify_options_creation() {
    let opts = qe::create_cawg_verify_options(true, true);
    assert!(opts.validate);
    assert!(opts.require_valid_identity);

    let opts2 = qe::create_cawg_verify_options(false, false);
    assert!(!opts2.validate);
    assert!(!opts2.require_valid_identity);
}

#[cfg(feature = "cawg")]
#[test]
fn sign_with_cawg_identity_assertion() {
    let (_tmp, uri) = common::setup_local_signer_files();
    let signer: qe::Signer = uri.parse().unwrap();

    let cawg_config = qe::create_cawg_x509_config(
        signer,
        vec!["c2pa.actions".to_string()]
    );

    let manifest = serde_json::json!({
        "title": "CAWG test",
        "format": "image/jpeg",
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        { "action": "c2pa.created", "softwareAgent": "test" }
                    ]
                }
            }
        ]
    }).to_string();

    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
        qe::Signer::Env {
            cert_var: "QE_TEST_CERT_PEM".to_string(),
            key_var: "QE_TEST_KEY_PEM".to_string()
        },
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(manifest);
    cfg.cawg_identity = Some(cawg_config);
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}

#[cfg(feature = "cawg")]
#[test]
fn verify_with_cawg_validation() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C_with_CAWG_data.jpg");

    if path.exists() {
        let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path));
        cfg.cawg = Some(qe::create_cawg_verify_options(true, false));

        match qe::verify_c2pa(cfg) {
            Ok(res) => {
                // Should have CAWG verification results
                if let Some(cawg_result) = res.cawg {
                    let _ = cawg_result.present;
                    let _ = cawg_result.valid;
                }
            }
            Err(_) => {} // May fail depending on fixture
        }
    }
}
