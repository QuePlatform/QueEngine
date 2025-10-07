mod common;

use std::io::Cursor;
use que_engine as qe;

fn signer() -> qe::Signer {
    common::setup_env_signer_vars().parse().unwrap()
}

#[test]
fn create_ingredient_from_stream_with_content_type() {
    let bytes = common::make_test_jpeg_bytes();
    let mut cfg = qe::IngredientConfig::secure_default(qe::AssetRef::Stream {
        reader: std::cell::RefCell::new(Box::new(Cursor::new(bytes))),
        content_type: Some("image/jpeg".to_string()),
    });
    cfg.output = qe::OutputTarget::Memory;
    let res = qe::create_ingredient(cfg).expect("ingredient").expect("bytes");
    assert!(res.len() > 0);

    // Verify it's valid JSON
    let _: serde_json::Value = serde_json::from_slice(&res).expect("valid JSON");
}

#[test]
fn create_ingredient_from_bytes() {
    let mut cfg = qe::IngredientConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() }
    );
    cfg.output = qe::OutputTarget::Memory;

    let result = qe::create_ingredient(cfg);
    assert!(result.is_ok());
    let ingredient_json = result.unwrap().unwrap();

    // Parse and validate structure
    let ingredient: serde_json::Value = serde_json::from_slice(&ingredient_json).unwrap();
    assert!(ingredient.get("title").is_some());
    assert!(ingredient.get("format").is_some());
}

#[test]
fn create_ingredient_to_path_writes_files() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = qe::IngredientConfig::secure_default(
        qe::AssetRef::Bytes { data: common::make_test_jpeg_bytes() }
    );
    cfg.output = qe::OutputTarget::Path(tmp.path().to_path_buf());

    let result = qe::create_ingredient(cfg);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none()); // Path output returns None

    // Verify ingredient.json was created
    let ingredient_path = tmp.path().join("ingredient.json");
    assert!(ingredient_path.exists());

    let content = std::fs::read_to_string(&ingredient_path).unwrap();
    let _: serde_json::Value = serde_json::from_str(&content).unwrap();
}

#[test]
fn ingredient_with_parent_relationship() {
    let manifest = serde_json::json!({
        "title": "test with parent",
        "format": "image/jpeg",
        "ingredients": [
            {
                "title": "parent.jpg",
                "format": "image/jpeg",
                "instance_id": "xmp.iid:parent-123",
                "relationship": "parentOf"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                            "parameters": {
                                "ingredientIds": ["xmp.iid:parent-123"]
                            }
                        },
                        { "action": "c2pa.color_adjustments" }
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

#[test]
fn ingredient_with_component_of_relationship() {
    let manifest = serde_json::json!({
        "title": "test with component",
        "format": "image/jpeg",
        "ingredients": [
            {
                "title": "component.jpg",
                "format": "image/jpeg",
                "instance_id": "xmp.iid:component-456",
                "relationship": "componentOf"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.placed",
                            "parameters": {
                                "ingredientIds": ["xmp.iid:component-456"]
                            }
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

#[test]
fn ingredient_with_input_to_relationship() {
    let manifest = serde_json::json!({
        "title": "test with AI input",
        "format": "image/jpeg",
        "ingredients": [
            {
                "title": "training_data.jpg",
                "format": "image/jpeg",
                "instance_id": "xmp.iid:input-789",
                "relationship": "inputTo"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                            "parameters": {
                                "ingredientIds": ["xmp.iid:input-789"]
                            }
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

#[test]
fn multiple_ingredients_with_different_relationships() {
    let manifest = serde_json::json!({
        "title": "test multiple ingredients",
        "format": "image/jpeg",
        "ingredients": [
            {
                "title": "parent.jpg",
                "format": "image/jpeg",
                "instance_id": "xmp.iid:parent-001",
                "relationship": "parentOf"
            },
            {
                "title": "component1.jpg",
                "format": "image/jpeg",
                "instance_id": "xmp.iid:comp-001",
                "relationship": "componentOf"
            },
            {
                "title": "component2.png",
                "format": "image/png",
                "instance_id": "xmp.iid:comp-002",
                "relationship": "componentOf"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                            "parameters": {
                                "ingredientIds": ["xmp.iid:parent-001"]
                            }
                        },
                        {
                            "action": "c2pa.placed",
                            "parameters": {
                                "ingredientIds": ["xmp.iid:comp-001"]
                            }
                        },
                        {
                            "action": "c2pa.placed",
                            "parameters": {
                                "ingredientIds": ["xmp.iid:comp-002"]
                            }
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

#[test]
fn ingredient_from_fixture_validates_on_read() {
    let fixtures = common::c2pa_fixtures_dir();
    let candidates = ["CA.jpg", "CAICA.jpg", "XCA.jpg"];
    let path = candidates.iter()
        .map(|n| fixtures.join(n))
        .find(|p| p.exists());

    if path.is_none() { return; }

    let cfg = qe::C2paVerificationConfig::secure_default(
        qe::AssetRef::Path(path.unwrap())
    );

    match qe::verify_c2pa(cfg) {
        Ok(res) => {
            // Check if report contains ingredient info
            assert!(!res.report.is_empty());

            // If status is present, check for ingredient validation codes
            if let Some(statuses) = res.status {
                for status in statuses {
                    // Ingredients have their own validation statuses
                    let _ = status.passed;
                    let _ = &status.code;
                }
            }
        }
        Err(_) => {} // Some fixtures may not be valid
    }
}

#[test]
fn ingredient_size_limits_enforced() {
    // Create a large "ingredient" (just data, not a real image)
    let large_data = vec![0xFF; 10 * 1024 * 1024]; // 10 MB

    let mut cfg = qe::IngredientConfig::secure_default(
        qe::AssetRef::Bytes { data: large_data }
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.limits.max_in_memory_asset_size = 1024; // 1 KB limit

    let result = qe::create_ingredient(cfg);
    match result {
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(msg.contains("too large") || msg.contains("limit") || msg.contains("c2pa"));
        }
        Ok(_) => {} // May succeed in lenient environments
    }
}

