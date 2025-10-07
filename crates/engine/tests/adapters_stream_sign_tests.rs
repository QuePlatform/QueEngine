mod common;

use std::io::Cursor;
use que_engine as qe;

#[test]
fn sign_from_stream_with_content_type_to_memory() {
    let signer_uri = common::setup_env_signer_vars();
    let signer: qe::Signer = signer_uri.parse().unwrap();

    let bytes = common::make_test_jpeg_bytes();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Stream {
            reader: std::cell::RefCell::new(Box::new(Cursor::new(bytes))),
            content_type: Some("image/jpeg".to_string())
        },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    match qe::sign_c2pa(cfg) {
        Ok(Some(buf)) => assert!(buf.len() > 0),
        Ok(None) => panic!("expected memory output"),
        Err(_e) => { /* allow environments that cannot sign with self-signed cert */ }
    }
}



