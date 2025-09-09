#[cfg(test)]
mod tests {
    use que_engine::{sign_c2pa, C2paConfig, AssetRef, OutputTarget, SigAlg, LimitsConfig, Signer};

    #[test]
    fn sniff_stream_without_content_type_jpeg() {
        // Synthetic JPEG-like stream (SOI marker)
        let mut data = vec![0xFF, 0xD8, 0xFF];
        data.resize(1024, 0u8);
        let cursor = std::io::Cursor::new(data);
        let reader: Box<dyn que_engine::domain::types::StreamReader> = Box::new(cursor);
        let asset = AssetRef::Stream { reader: std::cell::RefCell::new(reader), content_type: None };

        // Use dummy signer from env; if absent, this test should fail explicitly to avoid false positives
        let signer: Signer = "env:CERT_PEM,KEY_PEM".parse().expect("CERT_PEM/KEY_PEM env vars required for signing test");

        let cfg = C2paConfig {
            source: asset,
            output: OutputTarget::Memory,
            manifest_definition: None,
            parent: None,
            parent_base_dir: None,
            signer,
            signing_alg: SigAlg::Ps256,
            timestamper: None,
            remote_manifest_url: None,
            embed: true,
            trust_policy: None,
            skip_post_sign_validation: true,
            allow_insecure_remote_http: None,
            limits: LimitsConfig::defaults(),
            #[cfg(feature = "cawg")] cawg_identity: None,
        };

        // We assert specifically that we do not fail with UnsupportedType.
        match sign_c2pa(cfg) {
            Ok(_) => (),
            Err(e) => {
                let msg = format!("{e}");
                assert!(!msg.to_ascii_lowercase().contains("unsupportedtype"), "unexpected UnsupportedType error: {msg}");
            }
        }
    }
}
