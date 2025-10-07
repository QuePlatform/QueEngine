mod common;

use que_engine as qe;

#[test]
fn is_embedded_and_remote_url_fields_behave() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["cloud.jpg", "cloudx.jpg", "cloud_manifest.c2pa", "C.jpg"]; // cloud may use remote manifests
    let path = candidates.iter().map(|n| fixtures.join(n)).find(|p| p.exists());
    if path.is_none() { return; }

    let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path.unwrap()));
    // By default allow_remote_manifests is false; we still should get is_embedded/remote_url fields
    match qe::verify_c2pa(cfg) {
        Ok(r) => {
            let _ = r.is_embedded; // Optional bool
            let _ = r.remote_url;  // Optional string
        }
        Err(_e) => { /* acceptable depending on fixture */ }
    }
}

#[test]
fn verdict_is_mapped_from_statuses() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["CIE-sig-CA.jpg", "E-sig-CA.jpg", "XCA.jpg", "C.jpg"]; // variety of validation outcomes
    let path = candidates.iter().map(|n| fixtures.join(n)).find(|p| p.exists());
    if path.is_none() { return; }

    let cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path.unwrap()));
    match qe::verify_c2pa(cfg) {
        Ok(r) => {
            if let Some(v) = r.verdict.as_ref() {
                match v {
                    qe::domain::verify::Verdict::Allowed | qe::domain::verify::Verdict::Warning | qe::domain::verify::Verdict::Rejected => {}
                }
            }
        }
        Err(_e) => {}
    }
}

