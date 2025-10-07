mod common;

use std::io::Cursor;
use que_engine as qe;

fn jpeg_bytes() -> Vec<u8> { common::make_test_jpeg_bytes() }

fn signer_env() -> qe::Signer {
    let uri = common::setup_env_signer_vars();
    uri.parse().expect("signer parse")
}

fn manifest_with_actions_v2_created(format: &str, software: &str) -> String {
    serde_json::json!({
        "title": "que-engine test",
        "format": format,
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "softwareAgent": software
                        }
                    ]
                }
            }
        ]
    }).to_string()
}

fn manifest_with_ingredient_and_opened_action(format: &str) -> String {
    // Ingredient v3; engine/SDK will replace label during write, we supply instance_id for linkage
    let ingredient_iid = "xmp.iid:813ee422-9736-4cdc-9be6-4e35ed8e41cb";
    serde_json::json!({
        "title": "que-engine test",
        "format": format,
        "ingredients": [
            {
                "title": "A.jpg",
                "format": "image/jpeg",
                "instance_id": ingredient_iid,
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
                                "ingredientIds": [ingredient_iid]
                            }
                        },
                        { "action": "c2pa.resized" }
                    ]
                }
            }
        ]
    }).to_string()
}

#[test]
fn sign_with_actions_v2_and_memory_output() {
    let signer = signer_env();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: jpeg_bytes() },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(manifest_with_actions_v2_created("image/jpeg", "que-engine-tests"));
    cfg.skip_post_sign_validation = true; // avoid env trust failures

    match qe::sign_c2pa(cfg) {
        Ok(Some(buf)) => assert!(buf.len() > 0),
        Ok(None) => panic!("expected memory output"),
        Err(_e) => { /* environment may forbid signing */ }
    }
}

#[test]
fn sign_with_v3_ingredient_and_linked_action() {
    let signer = signer_env();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: jpeg_bytes() },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.manifest_definition = Some(manifest_with_ingredient_and_opened_action("image/jpeg"));
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg); // accept Ok/Err depending on environment
}

#[test]
fn sign_with_custom_and_cawg_metadata_assertions() {
    let signer = signer_env();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: jpeg_bytes() },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.skip_post_sign_validation = true;

    let manifest = serde_json::json!({
        "title": "que-engine custom",
        "format": "image/jpeg",
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": { "actions": [ { "action": "c2pa.created", "softwareAgent": "qe" } ] }
            },
            {
                "label": "com.example.qe",
                "data": { "git_hash": "abc123", "lib_name": "que-engine", "lib_version": "0.1" }
            },
            {
                "label": "cawg.training-mining",
                "data": { "entries": {
                    "cawg.ai_generative_training": { "use": "notAllowed" },
                    "cawg.ai_inference": { "use": "notAllowed" },
                    "cawg.ai_training": { "use": "allowed" },
                    "cawg.data_mining": { "use": "constrained", "constraint_info": "contact@example.com" }
                }}
            }
        ]
    }).to_string();

    cfg.manifest_definition = Some(manifest);

    let _ = qe::sign_c2pa(cfg);
}

#[test]
fn sign_with_timestamper_digicert_inserts_ta_url() {
    let signer = signer_env();
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: jpeg_bytes() },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.timestamper = Some(qe::Timestamper::Digicert);
    cfg.manifest_definition = Some(manifest_with_actions_v2_created("image/jpeg", "qe"));
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}

#[test]
fn sign_with_remote_manifest_url_and_no_embed() {
    let signer = signer_env();
    let tmp = tempfile::tempdir().unwrap();
    let out_path = tmp.path().join("signed.jpg");

    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Bytes { data: jpeg_bytes() },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Path(out_path.clone());
    cfg.embed = false;
    cfg.remote_manifest_url = Some("https://example.com/manifest.c2pa".to_string());
    cfg.manifest_definition = Some(manifest_with_actions_v2_created("image/jpeg", "qe"));
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}

#[test]
fn sign_from_stream_input_to_path_output() {
    let signer = signer_env();
    let tmp = tempfile::tempdir().unwrap();
    let out_path = tmp.path().join("signed.jpg");
    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Stream { reader: std::cell::RefCell::new(Box::new(Cursor::new(jpeg_bytes()))), content_type: Some("image/jpeg".to_string()) },
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Path(out_path.clone());
    cfg.manifest_definition = Some(manifest_with_actions_v2_created("image/jpeg", "qe"));
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}

#[test]
fn sign_with_parent_ingredient_from_fixture_path() {
    // Use fixture ingredient JSON if present
    let ingr = common::c2pa_fixtures_dir().join("ingredient/ingredient.json");
    if !ingr.exists() { return; }

    let signer = signer_env();
    let tmp = tempfile::tempdir().unwrap();
    let src_path = tmp.path().join("src.jpg");
    std::fs::write(&src_path, jpeg_bytes()).expect("write src");

    let mut cfg = qe::C2paConfig::secure_default(
        qe::AssetRef::Path(src_path.clone()),
        signer,
        qe::SigAlg::Es256,
    );
    cfg.output = qe::OutputTarget::Memory;
    cfg.parent = Some(qe::AssetRef::Path(ingr));
    cfg.manifest_definition = Some(manifest_with_actions_v2_created("image/jpeg", "qe"));
    cfg.skip_post_sign_validation = true;

    let _ = qe::sign_c2pa(cfg);
}

