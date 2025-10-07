use std::io::Write;
use std::path::{Path, PathBuf};

use image::{ImageBuffer, Rgb};
use rcgen::{Certificate, CertificateParams, KeyPair};
use tempfile::TempDir;

/// Create a tiny RGB JPEG image and return its bytes.
pub fn make_test_jpeg_bytes() -> Vec<u8> {
    // 8x8 solid color image
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(8, 8, |_x, _y| Rgb([128, 200, 50]));
    let dynimg = image::DynamicImage::ImageRgb8(img);
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut out);
    dynimg.write_to(&mut cursor, image::ImageOutputFormat::Jpeg(80)).expect("jpeg encode");
    out
}

/// Generate an ES256 self-signed certificate and key in PEM format using rcgen.
pub fn generate_es256_pem_pair() -> (String, String) {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key = KeyPair::generate(alg).expect("keypair");
    let mut params = CertificateParams::new(vec![]);
    params.alg = alg;
    // Ensure certificate is suitable for code signing
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    params.key_pair = Some(key);
    let cert = Certificate::from_params(params).expect("cert");
    let cert_pem = cert.serialize_pem().expect("cert pem");
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

/// Configure env vars with generated PEM data and return a signer URI string for env.
pub fn setup_env_signer_vars() -> String {
    let (cert_pem, key_pem) = generate_es256_pem_pair();
    // Use deterministic names to avoid accumulation; overwrite each run
    std::env::set_var("QE_TEST_CERT_PEM", cert_pem);
    std::env::set_var("QE_TEST_KEY_PEM", key_pem);
    "env:QE_TEST_CERT_PEM,QE_TEST_KEY_PEM".to_string()
}

/// Write PEM files to a temp dir and return (tempdir, signer URI string for local).
pub fn setup_local_signer_files() -> (TempDir, String) {
    let (cert_pem, key_pem) = generate_es256_pem_pair();
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::File::create(&cert_path).and_then(|mut f| f.write_all(cert_pem.as_bytes())).expect("write cert");
    std::fs::File::create(&key_path).and_then(|mut f| f.write_all(key_pem.as_bytes())).expect("write key");
    let uri = format!("local:{},{}", cert_path.display(), key_path.display());
    (dir, uri)
}

/// Minimal manifest definition JSON string suitable for unit tests.
pub fn minimal_manifest_def(format: &str) -> String {
    serde_json::json!({
        "title": "que-engine test",
        "format": format,
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        { "action": "c2pa.created", "softwareAgent": "que-engine-tests" }
                    ]
                }
            }
        ]
    }).to_string()
}

/// Crate root directory for the engine crate.
pub fn engine_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Repository root (two levels up from engine crate dir).
pub fn repo_root_dir() -> PathBuf {
    engine_crate_dir()
        .parent().map(Path::to_path_buf).unwrap()
        .parent().map(Path::to_path_buf).unwrap()
}

/// Path to the shared c2pa-rs test fixtures directory.
pub fn c2pa_fixtures_dir() -> PathBuf {
    repo_root_dir().join("c2pa-rs/sdk/tests/fixtures")
}


