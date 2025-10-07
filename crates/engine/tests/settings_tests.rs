mod common;

use que_engine as qe;

#[test]
fn limits_defaults_and_overrides() {
    let d = qe::LimitsConfig::defaults();
    assert!(d.max_in_memory_asset_size > 0);
    let mut cfg = qe::C2paVerificationConfig::secure_default(qe::AssetRef::Path(Default::default()));
    cfg.limits.max_stream_copy_size = 5 * 1024 * 1024; // 5MB
    assert_eq!(cfg.limits.max_stream_copy_size, 5 * 1024 * 1024);
}

#[test]
fn engine_defaults_values() {
    use qe::EngineDefaults as D;
    assert_eq!(D::ALLOW_REMOTE_MANIFESTS, false);
    assert!(matches!(D::OUTPUT_TARGET, qe::OutputTarget::Memory));
}



