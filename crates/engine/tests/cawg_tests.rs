// Feature-gated tests for CAWG support.
#![cfg(feature = "cawg")]

mod common;

use que_engine as qe;

#[test]
fn create_cawg_config_helpers() {
    let (_tmp, uri) = common::setup_local_signer_files();
    let signer: qe::Signer = uri.parse().unwrap();
    let cawg = qe::create_cawg_x509_config(signer, vec!["c2pa.actions".to_string()]);
    assert_eq!(cawg.referenced_assertions, vec!["c2pa.actions".to_string()]);
    let opts = qe::create_cawg_verify_options(true, true);
    assert!(opts.validate && opts.require_valid_identity);
}



