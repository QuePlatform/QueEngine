#[cfg(test)]
mod tests {
    use que_engine::{verify_c2pa, C2paVerificationConfig, AssetRef, VerifyMode, LimitsConfig};

    #[test]
    fn verify_stream_without_content_type_jpeg() {
        // Create a synthetic JPEG-like stream (SOI marker + padding)
        let mut data = vec![0xFF, 0xD8, 0xFF];
        data.resize(1024, 0u8);
        let cursor = std::io::Cursor::new(data);
        let reader: Box<dyn que_engine::domain::types::StreamReader> = Box::new(cursor);
        let asset = AssetRef::Stream { reader: std::cell::RefCell::new(reader), content_type: None };

        let cfg = C2paVerificationConfig {
            source: asset,
            mode: VerifyMode::Summary,
            policy: None,
            allow_remote_manifests: false,
            include_certificates: None,
            limits: LimitsConfig::defaults(),
            #[cfg(feature = "cawg")] cawg: None,
        };

        // Assert we do not get UnsupportedType. Any other error (e.g., invalid data) is acceptable here.
        match verify_c2pa(cfg) {
            Ok(_) => (),
            Err(e) => {
                let msg = format!("{e}");
                assert!(!msg.to_ascii_lowercase().contains("unsupportedtype"), "unexpected UnsupportedType error: {msg}");
            }
        }
    }
}
