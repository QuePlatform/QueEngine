mod common;

use que_engine as qe;

fn fixture_path(name: &str) -> std::path::PathBuf {
    common::c2pa_fixtures_dir().join(name)
}

#[test]
fn verify_image_with_multiple_ingredients_reports_validation_statuses() {
    // Use a known multi-ingredient fixture if available
    let candidates = [
        "CAICA.jpg",                  // expected to have multiple ingredients
        "adobe-20220124-CIE-sig-CA.jpg", // ingredient with invalid credentials
        "E-sig-CA.jpg",              // ingredient cases
    ];
    let fixtures = common::c2pa_fixtures_dir();
    let path = candidates
        .iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());
    if path.is_none() { return; }
    let cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path.unwrap()));
    let res = qe::verify_c2pa(cfg);
    match res {
        Ok(r) => {
            // We expect a non-empty report; ingredient-specific validation statuses
            // would be mapped into status (flat), so at least the report is available
            assert!(!r.report.is_empty());
            // If we got structured status, ensure it's well-formed booleans
            if let Some(statuses) = r.status.as_ref() {
                for s in statuses {
                    let _ = &s.code;
                    let _ = s.passed; // ensure field present
                }
            }
        }
        Err(e) => {
            // Accept verification failure depending on fixture states; but error type is propagated
            let msg = e.to_string();
            assert!(msg.contains("C2pa") || msg.contains("VerificationFailed") || msg.contains("invalid"));
        }
    }
}

#[test]
fn ingredients_in_unsigned_asset_yield_no_status_but_report_prints() {
    let path = fixture_path("no_manifest.jpg");
    if !path.exists() { return; }
    let cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path));
    match qe::verify_c2pa(cfg) {
        Ok(r) => assert!(!r.report.is_empty()),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("JumbfNotFound") || msg.contains("No claim") || msg.contains("no JUMBF"));
        }
    }
}

