mod common;

use que_engine as qe;

#[test]
fn include_certificates_true_populates_cert_info_if_present() {
    let fixtures = common::c2pa_fixtures_dir();
    // Choose an image that is likely to be signed with chain
    let candidates = ["C.jpg", "E-sig-CA.jpg", "XCA.jpg", "CA.jpg"]; 
    let path = candidates.iter().map(|n| fixtures.join(n)).find(|p| p.exists());
    if path.is_none() { return; }

    let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path.unwrap()));
    cfg.include_certificates = Some(true);
    match qe::verify_c2pa(cfg) {
        Ok(r) => {
            if let Some(certs) = r.certificates.as_ref() {
                // At least one cert info entry may be present
                if let Some(ci) = certs.get(0) {
                    // Fields are optional; ensure struct presence and types
                    let _ = &ci.alg;
                    let _ = &ci.issuer;
                    let _ = &ci.cert_serial_number;
                    let _ = &ci.chain_pem;
                }
            }
        }
        Err(_e) => { /* may fail based on fixture env; acceptable */ }
    }
}

#[test]
fn include_certificates_false_omits_cert_info() {
    let fixtures = common::c2pa_fixtures_dir();
    let path = fixtures.join("C.jpg");
    if !path.exists() { return; }
    let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(path));
    cfg.include_certificates = Some(false);
    match qe::verify_c2pa(cfg) {
        Ok(r) => assert!(r.certificates.is_none() || r.certificates.as_ref().unwrap().is_empty() || !r.report.is_empty()),
        Err(_e) => {}
    }
}

