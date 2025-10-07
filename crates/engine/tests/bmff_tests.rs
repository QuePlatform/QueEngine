// Feature-gated tests for fragmented BMFF support.
#![cfg(all(feature = "c2pa", feature = "bmff"))]

mod common;

use que_engine as qe;

#[test]
fn bmff_generate_uses_paths() {
    // Smoke test for API shape; actual input fixtures live in c2pa-rs, skip if absent
    let fixtures = common::c2pa_fixtures_dir();
    let init = fixtures.join("bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
    if !init.exists() { return; }
    let frags = fixtures.join("bunny/bunny_595491bps/BigBuckBunny_2s128.m4s");
    if !frags.exists() { return; }

    let (_tmp, signer_uri) = common::setup_local_signer_files();
    let signer: qe::Signer = signer_uri.parse().unwrap();
    let out_dir = tempfile::tempdir().unwrap();

    let mut cfg = qe::FragmentedBmffConfig::secure_default(
        init, frags, out_dir.path().to_path_buf(), signer, qe::SigAlg::Es256,
    );
    cfg.embed = true;
    cfg.manifest_definition = Some(common::minimal_manifest_def("video/mp4"));

    let _ = qe::generate_fragmented_bmff(cfg);
}



