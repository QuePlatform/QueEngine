// crates/engine/tests/c2pa_roundtrip.rs
#![cfg(feature = "c2pa")]

use que_engine::{
    create_ingredient,
    sign_c2pa,
    sign_c2pa_bytes,
    verify_c2pa,
    IngredientConfig,
    OutputTarget,
    SigAlg,
    Signer,
    Timestamper,
    TrustPolicyConfig,
    VerifyMode,
    C2paConfig,
    C2paVerificationConfig,
    AssetRef,
};
use rcgen::{Certificate, CertificateParams, IsCa};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

fn gen_self_signed_es256() -> (String, String) {
    let mut params = CertificateParams::new(vec!["que.test".to_string()]);
    // rcgen default is ECDSA P-256 + SHA-256, which matches ES256
    let cert = Certificate::from_params(params).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();
    (cert_pem, key_pem)
}

fn tiny_png() -> Vec<u8> {
    // 1x1 transparent PNG
    // Source: minimal valid PNG header + IHDR + IDAT + IEND
    // Safe for tests and recognized by most parsers.
    const PNG: &[u8] = &[
        0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n', // signature
        0x00, 0x00, 0x00, 0x0D, // IHDR length
        b'I', b'H', b'D', b'R',
        0x00, 0x00, 0x00, 0x01, // width 1
        0x00, 0x00, 0x00, 0x01, // height 1
        0x08, // bit depth
        0x06, // color type RGBA
        0x00, // compression
        0x00, // filter
        0x00, // interlace
        0x1F, 0x15, 0xC4, 0x89, // CRC
        0x00, 0x00, 0x00, 0x0A, // IDAT length (small)
        b'I', b'D', b'A', b'T',
        0x78, 0x9C, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, // zlib stream
        0x7B, 0x5E, 0x0D, 0x9B, // CRC
        0x00, 0x00, 0x00, 0x00, // IEND length
        b'I', b'E', b'N', b'D',
        0xAE, 0x42, 0x60, 0x82, // CRC
    ];
    PNG.to_vec()
}

#[test]
fn sign_and_verify_with_env_signer_memory() {
    let (cert_pem, key_pem) = gen_self_signed_es256();
    std::env::set_var("QUE_TEST_CERT_PEM", &cert_pem);
    std::env::set_var("QUE_TEST_KEY_PEM", &key_pem);

    let cfg = C2paConfig {
        source: AssetRef::Bytes {
            data: tiny_png(),
            ext: Some("png".into()),
        },
        output: OutputTarget::Memory,
        manifest_definition: None,
        parent: None,
        parent_base_dir: None,
        signer: Signer::from_str("env:QUE_TEST_CERT_PEM,QUE_TEST_KEY_PEM")
            .unwrap(),
        signing_alg: SigAlg::Es256,
        timestamper: Some(Timestamper::Custom(
            "http://timestamp.digicert.com".into(),
        )),
        remote_manifest_url: None,
        embed: true,
        skip_post_sign_validation: true,
    };

    let signed_bytes = sign_c2pa(cfg).expect("sign ok").unwrap();
    assert!(!signed_bytes.is_empty());

    let verify = C2paVerificationConfig {
        source: AssetRef::Bytes {
            data: signed_bytes,
            ext: Some("png".into()),
        },
        mode: VerifyMode::Info,
        policy: None,
        allow_remote_manifests: false,
    };

    let report = verify_c2pa(verify).expect("verify ok");
    assert!(!report.report.is_empty());
}

#[test]
fn sign_and_verify_with_local_signer_paths() {
    let (cert_pem, key_pem) = gen_self_signed_es256();
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    fs::write(&cert_path, cert_pem).unwrap();
    fs::write(&key_path, key_pem).unwrap();

    let src_path = dir.path().join("in.png");
    fs::write(&src_path, tiny_png()).unwrap();
    let out_path = dir.path().join("out.png");

    let cfg = C2paConfig {
        source: AssetRef::Path(src_path.clone()),
        output: OutputTarget::Path(out_path.clone()),
        manifest_definition: None,
        parent: None,
        parent_base_dir: None,
        signer: Signer::from_str(&format!(
            "local:{},{}",
            cert_path.display(),
            key_path.display()
        ))
        .unwrap(),
        signing_alg: SigAlg::Es256,
        timestamper: None,
        remote_manifest_url: None,
        embed: true,
        skip_post_sign_validation: false,
    };

    sign_c2pa(cfg).expect("sign ok");
    assert!(out_path.exists());

    let verify = C2paVerificationConfig {
        source: AssetRef::Path(out_path),
        mode: VerifyMode::Summary,
        policy: None,
        allow_remote_manifests: false,
    };
    let result = verify_c2pa(verify).expect("verify ok");
    assert!(!result.report.is_empty());
}

#[test]
fn create_ingredient_memory_and_folder() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("in.png");
    fs::write(&src_path, tiny_png()).unwrap();

    // Memory output
    let mem = create_ingredient(IngredientConfig {
        source: AssetRef::Path(src_path.clone()),
        output: OutputTarget::Memory,
    })
    .expect("ingredient mem ok")
    .expect("bytes expected");
    let as_str = String::from_utf8(mem).unwrap();
    let _json: serde_json::Value = serde_json::from_str(&as_str).unwrap();

    // Folder output
    let out_dir = dir.path().join("ingredient_out");
    create_ingredient(IngredientConfig {
        source: AssetRef::Path(src_path),
        output: OutputTarget::Path(out_dir.clone()),
    })
    .expect("ingredient folder ok");
    let json_path = out_dir.join("ingredient.json");
    assert!(json_path.exists());
    let _parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(json_path).unwrap()).unwrap();
}

#[test]
fn verify_with_trust_policy_self_signed_anchor() {
    let (cert_pem, key_pem) = gen_self_signed_es256();
    std::env::set_var("QUE_TEST_CERT_PEM2", &cert_pem);
    std::env::set_var("QUE_TEST_KEY_PEM2", &key_pem);

    // Sign
    let signed = sign_c2pa_bytes(
        &tiny_png(),
        C2paConfig {
            source: AssetRef::Bytes {
                data: vec![], // will be replaced by helper
                ext: None,
            },
            output: OutputTarget::Memory,
            manifest_definition: None,
            parent: None,
            parent_base_dir: None,
            signer: Signer::from_str("env:QUE_TEST_CERT_PEM2,QUE_TEST_KEY_PEM2")
                .unwrap(),
            signing_alg: SigAlg::Es256,
            timestamper: None,
            remote_manifest_url: None,
            embed: true,
            skip_post_sign_validation: true,
        },
    )
    .expect("sign ok");

    // Verify with trust anchors set to the self-signed cert
    let policy = TrustPolicyConfig {
        anchors: Some(cert_pem.clone().into_bytes()),
        allowed_list: None,
        allowed_ekus: None,
    };

    let result = verify_c2pa(C2paVerificationConfig {
        source: AssetRef::Bytes {
            data: signed,
            ext: Some("png".into()),
        },
        mode: VerifyMode::Info,
        policy: Some(policy),
        allow_remote_manifests: false,
    })
    .expect("verify ok");

    // If verdict is present, it must not be Rejected
    if let Some(v) = result.verdict {
        match v {
            que_engine::domain::verify::Verdict::Rejected => {
                panic!("verification rejected with provided trust anchors")
            }
            _ => {}
        }
    }
}

#[test]
fn verify_unsigned_asset_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("plain.png");
    fs::write(&path, tiny_png()).unwrap();

    let verify = C2paVerificationConfig {
        source: AssetRef::Path(path),
        mode: VerifyMode::Summary,
        policy: None,
        allow_remote_manifests: false,
    };

    // Reader::from_file should fail because there's no manifest
    let err = verify_c2pa(verify).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("c2pa") || msg.contains("verification") || msg.contains("Failed"),
        "unexpected error: {msg}"
    );
}

#[test]
fn concurrent_sign_verify_is_safe() {
    let (cert_pem, key_pem) = gen_self_signed_es256();
    std::env::set_var("QUE_CERT_CONC", &cert_pem);
    std::env::set_var("QUE_KEY_CONC", &key_pem);

    let signer = Signer::from_str("env:QUE_CERT_CONC,QUE_KEY_CONC").unwrap();
    let png = tiny_png();
    let signer = Arc::new(signer);

    let mut handles = Vec::new();
    for i in 0..8 {
        let s = signer.clone();
        let png_bytes = png.clone();
        handles.push(thread::spawn(move || {
            // sign
            let out = sign_c2pa(C2paConfig {
                source: AssetRef::Bytes {
                    data: png_bytes,
                    ext: Some("png".into()),
                },
                output: OutputTarget::Memory,
                manifest_definition: None,
                parent: None,
                parent_base_dir: None,
                signer: (*s).clone(),
                signing_alg: SigAlg::Es256,
                timestamper: None,
                remote_manifest_url: None,
                embed: true,
                skip_post_sign_validation: i % 2 == 0,
            })
            .expect("sign ok")
            .unwrap();

            // verify
            let _ = verify_c2pa(C2paVerificationConfig {
                source: AssetRef::Bytes {
                    data: out,
                    ext: Some("png".into()),
                },
                mode: VerifyMode::Summary,
                policy: None,
                allow_remote_manifests: false,
            })
            .expect("verify ok");
        }));
    }

    for h in handles {
        h.join().expect("thread ok");
    }
}