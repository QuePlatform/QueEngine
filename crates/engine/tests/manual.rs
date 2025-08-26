// crates/engine/tests/manual.rs
use que_engine::{
    sign_c2pa, verify_c2pa, AssetRef, C2paConfig, C2paVerificationConfig,
    OutputTarget, SigAlg, Signer, VerifyMode,
};

#[test]
fn manual_sign_and_verify() {
    // Point to a test asset (e.g. a PNG or JPEG)
    let asset_path = std::path::PathBuf::from("tests/data/sample2.jpg");

    // Use a local signer (PEM cert + key you generate with openssl)
    // Example: export CERT_PEM, KEY_PEM with your PEM contents
    // and use: "env:CERT_PEM,KEY_PEM" or point to files with "local:/path/cert.pem,/path/key.pem"
    let signer: Signer = std::env::var("TEST_SIGNER_URI")
        .unwrap_or_else(|_| "env:CERT_PEM,KEY_PEM".to_string())
        .parse()
        .unwrap();

    // Build config
    let cfg = C2paConfig {
        source: AssetRef::Path(asset_path.clone()),
        output: OutputTarget::Memory,
        manifest_definition: None,
        parent: None,
        parent_base_dir: None,
        signer,
        signing_alg: SigAlg::Es256,
        timestamper: None,
        remote_manifest_url: None,
        embed: true,
        trust_policy: None,
        skip_post_sign_validation: false,
    };

    // Generate signed asset
    let signed_bytes = sign_c2pa(cfg).expect("signing failed");
    assert!(signed_bytes.is_some());

    // Verify
    let verify_cfg = C2paVerificationConfig {
        source: AssetRef::Bytes { data: signed_bytes.unwrap() },
        mode: VerifyMode::Summary,
        policy: None,
        allow_remote_manifests: false,
        include_certificates: None,
    };

    let result = verify_c2pa(verify_cfg).expect("verification failed");
    println!("Verification report: {}", result.report);
}