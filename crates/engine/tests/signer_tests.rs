mod common;

use que_engine as qe;

#[test]
fn parse_env_signer() {
    let _ = common::setup_env_signer_vars();
    let signer: qe::Signer = "env:QE_TEST_CERT_PEM,QE_TEST_KEY_PEM".parse().unwrap();
    // Resolve only if c2pa feature is enabled; otherwise ensure construction succeeds
    #[cfg(feature = "c2pa")]
    {
        let _ = signer.resolve(c2pa::SigningAlg::Es256).unwrap();
    }
}

#[test]
fn parse_local_signer() {
    let (_dir, uri) = common::setup_local_signer_files();
    let signer: qe::Signer = uri.parse().unwrap();
    #[cfg(feature = "c2pa")]
    {
        let _ = signer.resolve(c2pa::SigningAlg::Es256).unwrap();
    }
}

#[test]
fn invalid_signer_scheme() {
    let err = "foo:bar".parse::<qe::Signer>().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("Invalid"));
}



