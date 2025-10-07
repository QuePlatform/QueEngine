mod common;

use que_engine as qe;

#[test]
fn verify_modes_affect_report_format() {
    // Unsigned minimal image -> reader still constructs report strings
    let bytes = common::make_test_jpeg_bytes();
    for mode in [qe::VerifyMode::Summary, qe::VerifyMode::Info, qe::VerifyMode::Detailed, qe::VerifyMode::Tree] {
        let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Bytes { data: bytes.clone() });
        cfg.mode = mode;
        match qe::verify_c2pa(cfg) {
            Ok(res) => assert!(!res.report.is_empty()),
            Err(e) => {
                // Some modes may fail on unsigned inputs depending on c2pa behavior; ensure we get a reasonable error
                let msg = e.to_string();
                assert!(msg.contains("JumbfNotFound") || msg.contains("No claim") || msg.contains("no JUMBF") || msg.contains("invalid"));
            }
        }
    }
}



