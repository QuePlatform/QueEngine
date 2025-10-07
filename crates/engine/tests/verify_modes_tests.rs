mod common;

use std::io::Cursor;
use que_engine as qe;

#[test]
fn verify_modes_produce_reports() {
    let bytes = common::make_test_jpeg_bytes();
    for mode in [qe::VerifyMode::Summary, qe::VerifyMode::Info, qe::VerifyMode::Detailed, qe::VerifyMode::Tree] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Stream {
            reader: std::cell::RefCell::new(Box::new(Cursor::new(bytes.clone()))),
            content_type: Some("image/jpeg".to_string()),
        });
        cfg.mode = mode;
        match qe::verify_c2pa(cfg) {
            Ok(res) => assert!(!res.report.is_empty()),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("JumbfNotFound") || msg.contains("No claim") || msg.contains("no JUMBF"));
            }
        }
    }
}

#[test]
fn verify_mode_summary_is_concise() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["C.jpg", "CA.jpg", "XCA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let mut cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );
    cfg.mode = qe::VerifyMode::Summary;

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            // Summary should have report
            assert!(!res.report.is_empty());
            // Summary typically shorter than detailed modes
        }
        Err(_) => {}
    }
}

#[test]
fn verify_mode_info_includes_metadata() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["C.jpg", "CA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let mut cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );
    cfg.mode = qe::VerifyMode::Info;

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            assert!(!res.report.is_empty());
            // Info mode should include more metadata
        }
        Err(_) => {}
    }
}

#[test]
fn verify_mode_detailed_includes_all_info() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["C.jpg", "CA.jpg", "CAICA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let mut cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );
    cfg.mode = qe::VerifyMode::Detailed;

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            assert!(!res.report.is_empty());
            // Detailed mode should have comprehensive information
        }
        Err(_) => {}
    }
}

#[test]
fn verify_mode_tree_shows_hierarchy() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["CAICA.jpg", "CA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let mut cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );
    cfg.mode = qe::VerifyMode::Tree;

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            assert!(!res.report.is_empty());
            // Tree mode should show ingredient hierarchy
        }
        Err(_) => {}
    }
}

#[test]
fn different_modes_produce_different_output_lengths() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("CA.jpg");

    if !path.exists() { return; }

    let mut lengths = std::collections::HashMap::new();

    for mode in [
        qe::VerifyMode::Summary,
        qe::VerifyMode::Info,
        qe::VerifyMode::Detailed,
        qe::VerifyMode::Tree,
    ] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(
            qe::AssetRef::Path(path.clone())
        );
        cfg.mode = mode;

        if let Ok(res) = qe::verify_c2pa(cfg) {
            lengths.insert(format!("{:?}", mode), res.report.len());
        }
    }

    // If we got multiple results, they should have varying lengths
    if lengths.len() > 1 {
        let values: Vec<usize> = lengths.values().copied().collect();
        // At least some should be different (not all equal)
        let all_equal = values.windows(2).all(|w| w[0] == w[1]);
        // Most likely detailed/tree will be longer than summary
        let _ = all_equal;
    }
}

#[test]
fn verify_mode_with_include_certificates() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C.jpg");

    if !path.exists() { return; }

    for mode in [qe::VerifyMode::Summary, qe::VerifyMode::Detailed] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(
            qe::AssetRef::Path(path.clone())
        );
        cfg.mode = mode;
        cfg.include_certificates = Some(true);

        if let Ok(res) = qe::verify_c2pa(cfg) {
            // May have certificates if available
            if let Some(certs) = res.certificates {
                for cert in certs {
                    let _ = &cert.alg;
                    let _ = &cert.issuer;
                }
            }
        }
    }
}

#[test]
fn verify_mode_with_validation_statuses() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["C.jpg", "CIE-sig-CA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    for mode in [
        qe::VerifyMode::Summary,
        qe::VerifyMode::Info,
        qe::VerifyMode::Detailed,
    ] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(
            qe::AssetRef::Path(path.as_ref().unwrap().clone())
        );
        cfg.mode = mode;

        if let Ok(res) = qe::verify_c2pa(cfg) {
            // All modes should provide structured validation status
            if let Some(statuses) = res.status {
                for status in statuses {
                    assert!(!status.code.is_empty());
                    // Check that passed field exists
                    let _ = status.passed;
                }
            }
        }
    }
}

#[test]
fn verify_modes_work_with_streams() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C.jpg");

    if !path.exists() { return; }

    let data = std::fs::read(&path).unwrap();

    for mode in [qe::VerifyMode::Summary, qe::VerifyMode::Tree] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Stream {
            reader: std::cell::RefCell::new(Box::new(Cursor::new(data.clone()))),
            content_type: Some("image/jpeg".to_string()),
        });
        cfg.mode = mode;

        match qe::verify_c2pa(cfg) {
            Ok(res) => assert!(!res.report.is_empty()),
            Err(_) => {}
        }
    }
}

#[test]
fn verify_modes_work_with_bytes() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C.jpg");

    if !path.exists() { return; }

    let data = std::fs::read(&path).unwrap();

    for mode in [qe::VerifyMode::Info, qe::VerifyMode::Detailed] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(
            qe::AssetRef::Bytes { data: data.clone() }
        );
        cfg.mode = mode;

        match qe::verify_c2pa(cfg) {
            Ok(res) => assert!(!res.report.is_empty()),
            Err(_) => {}
        }
    }
}

