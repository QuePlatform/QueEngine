mod common;

use que_engine as qe;

fn signer() -> qe::Signer {
    common::setup_env_signer_vars().parse().unwrap()
}

#[test]
fn sign_with_digital_source_type_variations() {
    let source_types = [
        "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
        "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
        "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia",
    ];

    for source_type in source_types {
        let manifest = serde_json::json!({
            "title": "digital source test",
            "format": "image/jpeg",
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "softwareAgent": "test",
                                "digitalSourceType": source_type
                            }
                        ]
                    }
                }
            ]
        }).to_string();

        let mut cfg = qe::C2paConfig::secure_default(
            qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
            signer(),
            qe::SigAlg::Es256,
        );
        cfg.output = qe::OutputTarget::Memory;
        cfg.manifest_definition = Some(manifest);
        cfg.skip_post_sign_validation = true;

        let _ = qe::sign_c2pa(cfg);
    }
}

#[test]
fn sign_with_standard_c2pa_actions() {
    let actions = [
        ("c2pa.color_adjustments", Some(serde_json::json!({
            "com.adobe.acr": "Contrast2012",
            "com.adobe.acr.value": "26"
        }))),
        ("c2pa.resized", Some(serde_json::json!({
            "width": 800,
            "height": 600
        }))),
        ("c2pa.cropped", Some(serde_json::json!({
            "x": 10,
            "y": 10,
            "width": 200,
            "height": 150
        }))),
        ("c2pa.transcoded", None),
    ];

    for (action_name, parameters) in actions {
        let mut actions_array = vec![
            serde_json::json!({
                "action": "c2pa.created",
                "softwareAgent": "test"
            })
        ];

        let mut action_obj = serde_json::json!({
            "action": action_name
        });

        if let Some(params) = parameters {
            action_obj["parameters"] = params;
        }

        actions_array.push(action_obj);

        let manifest = serde_json::json!({
            "title": "actions test",
            "format": "image/jpeg",
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {
                        "actions": actions_array
                    }
                }
            ]
        }).to_string();

        let mut cfg = qe::C2paConfig::secure_default(
            qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
            signer(),
            qe::SigAlg::Es256,
        );
        cfg.output = qe::OutputTarget::Memory;
        cfg.manifest_definition = Some(manifest);
        cfg.skip_post_sign_validation = true;

        let _ = qe::sign_c2pa(cfg);
    }
}

#[test]
fn sign_with_exif_metadata_assertion() {
    let manifest = serde_json::json!({
        "title": "EXIF metadata test",
        "format": "image/jpeg",
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        { "action": "c2pa.created", "softwareAgent": "test" }
                    ]
                }
            },
            {
                "label": "stds.exif",
                "data": {
                    "@context": {
                        "exif": "http://ns.adobe.com/exif/1.0/"
                    },
                    "exif:GPSVersionID": "2.2.0.0",
                    "exif:GPSLatitude": "39,21.102N",
                    "exif:GPSLongitude": "74,26.5737W",
                    "exif:GPSAltitudeRef": 0,
                    "exif:GPSAltitude": "100963/29890",
                    "exif:GPSTimeStamp": "2019-09-22T18:22:57Z"
                }
            }
        ]
    }).to_string();

    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
        signer(),
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(manifest);
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}

#[test]
fn sign_with_iptc_metadata_assertion() {
    let manifest = serde_json::json!({
        "title": "IPTC metadata test",
        "format": "image/jpeg",
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        { "action": "c2pa.created", "softwareAgent": "test" }
                    ]
                }
            },
            {
                "label": "stds.iptc",
                "data": {
                    "@context": {
                        "Iptc4xmpCore": "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/",
                        "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "photoshop": "http://ns.adobe.com/photoshop/1.0/",
                        "plus": "http://ns.useplus.org/ldf/xmp/1.0/",
                        "xmp": "http://ns.adobe.com/xap/1.0/",
                        "xmpDM": "http://ns.adobe.com/xmp/1.0/DynamicMedia/",
                        "xmpRights": "http://ns.useplus.org/ldf/xmp/1.0/",
                        "xmpRights": "http://ns.adobe.com/xap/1.0/rights/"
                    },
                    "dc:creator": ["Test Photographer"],
                    "Iptc4xmpExt:DigitalSourceType": "https://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
                    "dc:rights": "Copyright (C) 2024 Test. All Rights Reserved.",
                    "xmpRights:WebStatement": "http://example.com/terms.html"
                }
            }
        ]
    }).to_string();

    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() },
        signer(),
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(manifest);
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}
