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
    let signer: Signer = "local:tests/data/cert.pem,tests/data/key.pem"
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
        skip_post_sign_validation: true,
    };

    // Generate signed asset
    let signed_bytes = sign_c2pa(cfg).expect("signing failed");
    assert!(signed_bytes.is_some());

    // Verify
    let verify_cfg = C2paVerificationConfig {
        source: AssetRef::Bytes {
            data: signed_bytes.unwrap(),
            ext: Some("jpg".into()),
        },
        mode: VerifyMode::Summary,
        policy: None,
        allow_remote_manifests: false,
    };

    let result = verify_c2pa(verify_cfg).expect("verification failed");
    println!("Verification report: {}", result.report);
}