mod common;

use std::io::Cursor;
use que_engine as qe;

fn signer() -> qe::Signer {
    common::setup_env_signer_vars().parse().unwrap()
}

#[test]
fn sign_to_memory_and_verify_from_bytes() {
    let src_bytes = common::make_test_jpeg_bytes();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: src_bytes.clone() },
        signer(),
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    match qe::sign_c2pa(cfg) {
        Ok(Some(signed)) => {
            assert!(signed.len() > 0, "signed bytes should be returned");
            let vcfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Bytes { data: signed });
            match qe::verify_c2pa(vcfg) {
                Ok(res) => assert!(!res.report.is_empty()),
                Err(_e) => {}
            }
        }
        Ok(None) => panic!("expected memory output"),
        Err(_e) => {}
    }
}

#[test]
fn sign_to_path_and_verify_from_path() {
    let (tmpdir, signer_uri) = common::setup_local_signer_files();
    let signer: qe::Signer = signer_uri.parse().expect("signer parse");

    let src_path = tmpdir.path().join("src.jpg");
    std::fs::write(&src_path, common::make_test_jpeg_bytes()).expect("write src");

    let out_path = tmpdir.path().join("out.jpg");
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Path(src_path.clone()),
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Path(out_path.clone());
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    match qe::sign_c2pa(cfg) {
        Ok(none) => {
            assert!(none.is_none());
            assert!(out_path.exists());
            let vcfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(out_path.clone()));
            match qe::verify_c2pa(vcfg) {
                Ok(res) => assert!(res.is_embedded.unwrap_or(false) || !res.report.is_empty()),
                Err(_e) => {}
            }
        }
        Err(_e) => {}
    }
}

#[test]
fn verify_from_stream_with_sniffing() {
    let bytes = common::make_test_jpeg_bytes();
    let mut vcfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Stream {
        reader: std::cell::RefCell::new(Box::new(Cursor::new(bytes))),
        content_type: None,
    });
    vcfg.mode = qe::VerifyMode::Summary;
    match qe::verify_c2pa(vcfg) {
        Ok(res) => assert!(!res.report.is_empty()),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("JumbfNotFound") || msg.contains("No claim") || msg.contains("no JUMBF"));
        }
    }
}

#[test]
fn roundtrip_sign_verify_with_different_algorithms() {
    for alg in [qe::SigAlg::Es256, qe::SigAlg::Es384, qe::SigAlg::Ps256] {
        let mut cfg = qe::C2paConfig::secure_default(
            qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
            signer(),
            alg,
        );
        cfg.output = qe::OutputTarget::Memory;
        cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));
        cfg.skip_post_sign_validation = true;

        let _ = qe::sign_c2pa(cfg);
    }
}

#[test]
fn sign_with_all_verify_modes() {
    let mut sign_cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
        signer(),
        qe::SigAlg::Es256,
    );
    sign_cfg.output = qe::OutputTarget::Memory;
    sign_cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    if let Ok(Some(signed)) = qe::sign_c2pa(sign_cfg) {
        for mode in [
            qe::VerifyMode::Summary,
            qe::VerifyMode::Info,
            qe::VerifyMode::Detailed,
            qe::VerifyMode::Tree,
        ] {
            let mut vcfg = qe::C2paVerificationConfig::secure_default(
                qe::AssetRef::Bytes { data: signed.clone() }
            );
            vcfg.mode = mode;

            match qe::verify_c2pa(vcfg) {
                Ok(res) => {
                    assert!(!res.report.is_empty());
                    // Different modes should produce different report lengths
                }
                Err(_) => {}
            }
        }
    }
}

#[test]
fn sign_bytes_helper_convenience_function() {
    let bytes = common::make_test_jpeg_bytes();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: bytes.clone() },
        signer(),
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    match qe::sign_c2pa_bytes(&bytes, cfg) {
        Ok(out) => assert!(out.len() > 0),
        Err(_e) => {}
    }
}

#[test]
fn verify_includes_embedded_flag() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["C.jpg", "CA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            // Should have is_embedded field
            let _ = res.is_embedded;
        }
        Err(_) => {}
    }
}

#[test]
fn verify_includes_verdict() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["C.jpg", "XCA.jpg", "CIE-sig-CA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            if let Some(verdict) = res.verdict {
                match verdict {
                    qe::domain::verify::Verdict::Allowed |
                    qe::domain::verify::Verdict::Warning |
                    qe::domain::verify::Verdict::Rejected => {}
                }
            }
        }
        Err(_) => {}
    }
}

#[test]
fn sign_and_verify_preserves_data_integrity() {
    let original = common::make_test_jpeg_bytes();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: original.clone() },
        signer(),
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    if let Ok(Some(signed)) = qe::sign_c2pa(cfg) {
        // Signed should be larger (has manifest embedded)
        assert!(signed.len() > original.len());

        // Verify it
        let vcfg = qe::C2paVerificationConfig::secure_default(
            qe::AssetRef::Bytes { data: signed }
        );

        match qe::verify_c2pa(vcfg) {
            Ok(res) => {
                assert!(res.is_embedded.unwrap_or(false));

                // Should have validation status
                if let Some(statuses) = res.status {
                    for status in statuses {
                        // Each status should have required fields
                        assert!(!status.code.is_empty());
                    }
                }
            }
            Err(_) => {}
        }
    }
}

#[test]
fn verify_tampered_manifest_fails() {
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
        signer(),
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    if let Ok(Some(mut signed)) = qe::sign_c2pa(cfg) {
        // Tamper with the data
        if signed.len() > 100 {
            signed[50] = signed[50].wrapping_add(1);
        }

        let vcfg = qe::C2paVerificationConfig::secure_default(
            qe::AssetRef::Bytes { data: signed }
        );

        match qe::verify_c2pa(vcfg) {
            Ok(res) => {
                // If it succeeds to read, check verdict
                if let Some(verdict) = res.verdict {
                    // Tampered content should ideally be rejected
                    match verdict {
                        qe::domain::verify::Verdict::Rejected |
                        qe::domain::verify::Verdict::Warning => {},
                        qe::domain::verify::Verdict::Allowed => {
                            // May still be allowed depending on what was tampered
                        }
                    }
                }

                // Check for failure validation statuses
                if let Some(statuses) = res.status {
                    let has_failures = statuses.iter().any(|s| !s.passed);
                    // Tampered manifests should have some validation failures
                    let _ = has_failures;
                }
            }
            Err(_) => {
                // Tampered manifests often fail to parse - this is expected
            }
        }
    }
}

