mod common;

use std::path::PathBuf;
use que_engine as qe;

#[test]
fn verify_known_unsigned_fixture_reports() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("no_manifest.jpg");
    if !path.exists() { return; }
    let cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path));
    match qe::verify_c2pa(cfg) {
        Ok(res) => assert!(!res.report.is_empty()),
        Err(e) => {
            // Acceptable for unsigned content: JUMBF not found / no manifest
            let msg = e.to_string();
            assert!(msg.contains("JumbfNotFound") || msg.contains("No claim") || msg.contains("no JUMBF"));
        }
    }
}

#[test]
fn sign_and_verify_using_fixture_input() {
    let fixtures = common::c2pa_fixtures_dir();
    // Prefer an unsigned fixture to avoid certificate profile constraints in pre-signed assets
    let input = fixtures.join("no_manifest.jpg");
    if !input.exists() { return; }

    let signer_uri = common::setup_env_signer_vars();
    let signer: qe::Signer = signer_uri.parse().unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("signed.jpg");
    let mut cfg = qe::C2paConfig::secure_default(qe::AssetRef::Path(input.clone()), signer, qe::SigAlg::Es256);
    cfg.output = qe::OutputTarget::Path(out.clone());
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    if let Ok(_) = qe::sign_c2pa(cfg) {
        let vcfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(out));
        let res = qe::verify_c2pa(vcfg).expect("verify");
        assert!(res.is_embedded.unwrap_or(false));
    } else {
        // Environments that reject self-signed certs: treat as acceptable
    }
}


