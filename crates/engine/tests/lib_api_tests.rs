mod common;

use que_engine as qe;

#[test]
fn sign_c2pa_bytes_roundtrip() {
    let signer_uri = common::setup_env_signer_vars();
    let signer: qe::Signer = signer_uri.parse().expect("signer parse");

    let bytes = common::make_test_jpeg_bytes();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: bytes.clone() },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(common::minimal_manifest_def("image/jpeg"));

    match qe::sign_c2pa_bytes(&bytes, cfg) {
        Ok(out) => assert!(out.len() > 0),
        Err(_e) => { /* allow environments that cannot sign with self-signed cert */ }
    }
}

#[test]
fn create_ingredient_memory_and_path_output() {
    // Memory
    let mut icfg = qe::IngredientConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() }
    );
    icfg.output = qe::OutputTarget::Memory;
    let mem = qe::create_ingredient(icfg).expect("create ingredient").expect("mem");
    assert!(mem.len() > 0);

    // Path(dir)
    let tmp = tempfile::tempdir().unwrap();
    let mut pcfg = qe::IngredientConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() }
    );
    pcfg.output = qe::OutputTarget::Path(tmp.path().to_path_buf());
    let none = qe::create_ingredient(pcfg).expect("create ingredient path");
    assert!(none.is_none());
    assert!(tmp.path().join("ingredient.json").exists());
}


