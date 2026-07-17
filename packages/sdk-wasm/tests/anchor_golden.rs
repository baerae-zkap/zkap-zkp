//! Golden cross-runtime tests for anchor generation, deriveSelector
//! membership, and audience hashing.
//!
//! Runs the SAME vectors as packages/sdk-node/__test__/anchor-golden.spec.ts
//! (golden/anchor-vectors.json, regenerated via
//! `node scripts/generate-anchor-golden.mjs`), so any node/wasm divergence —
//! quoting, padding, selector search order, error codes — fails here.
//!
//! Run with:
//!   wasm-pack test --node packages/sdk-wasm

use js_sys::{Reflect, JSON};
use serde_json::Value;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

const GOLDEN: &str = include_str!("../../../golden/anchor-vectors.json");

fn golden() -> Value {
    serde_json::from_str(GOLDEN).expect("parse golden/anchor-vectors.json")
}

/// Build a plain JS value from a serde_json subtree via JSON.parse (plain
/// objects, not Maps — see hash_tests.rs).
fn jsv(v: &Value) -> JsValue {
    JSON::parse(&v.to_string()).expect("JSON.parse of golden subtree")
}

/// Compact-JSON render of a JS value, comparable with `Value::to_string()`.
fn js_json(v: &JsValue) -> String {
    JSON::stringify(v)
        .expect("JSON.stringify")
        .as_string()
        .expect("stringify result is a string")
}

fn get(v: &JsValue, key: &str) -> JsValue {
    Reflect::get(v, &JsValue::from_str(key)).expect(key)
}

fn string_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

#[wasm_bindgen_test]
fn golden_anchors_match_node() {
    let g = golden();
    for (name, anchor) in g["anchors"].as_object().expect("anchors object") {
        let result = zkap_zkp_wasm::generate_anchor(jsv(&g["config3of6"]), jsv(&anchor["secrets6"]))
            .unwrap_or_else(|e| panic!("generateAnchor '{name}' failed: {:?}", e));
        let evaluations = get(&result, "evaluations");
        assert_eq!(
            js_json(&evaluations),
            anchor["evaluations"].to_string(),
            "anchor '{name}' evaluations diverged from node"
        );
    }
}

#[wasm_bindgen_test]
fn golden_derive_selector_matches_node() {
    let g = golden();
    for case in g["deriveCases"].as_array().expect("deriveCases array") {
        let name = case["name"].as_str().unwrap_or("?");
        let mut evals = string_vec(&g["anchors"][case["anchor"].as_str().expect("anchor name")]["evaluations"]);
        if let Some(n) = case.get("anchorSlice").and_then(Value::as_u64) {
            evals.truncate(n as usize);
        }
        let result =
            zkap_zkp_wasm::derive_selector(jsv(&g["config3of6"]), jsv(&case["secrets"]), evals);

        if case["expect"]["selector"].is_array() {
            let selector = result.unwrap_or_else(|e| panic!("deriveSelector '{name}' failed: {:?}", e));
            assert_eq!(
                js_json(&selector),
                case["expect"]["selector"].to_string(),
                "selector for '{name}' diverged from node"
            );
        } else {
            let err = result.expect_err("expected deriveSelector error");
            let code = get(&err, "code").as_string().expect("error.code string");
            assert_eq!(
                code,
                case["expect"]["errorCode"].as_str().expect("errorCode"),
                "error.code for '{name}'"
            );
            let message = get(&err, "message").as_string().expect("error.message string");
            let needle = case["expect"]["messageIncludes"].as_str().expect("messageIncludes");
            assert!(
                message.contains(needle),
                "message {message:?} for '{name}' should include {needle:?}"
            );
        }
    }
}

#[wasm_bindgen_test]
fn golden_aud_hashes_match_node() {
    let g = golden();
    for (i, case) in g["audHashCases"].as_array().expect("audHashCases").iter().enumerate() {
        let config = if case["config"] == "1of1" { &g["config1of1"] } else { &g["config3of6"] };
        let result =
            zkap_zkp_wasm::generate_aud_hash(jsv(config), string_vec(&case["audiences"]))
                .unwrap_or_else(|e| panic!("generateAudHash case {i} failed: {:?}", e));
        assert_eq!(
            js_json(&get(&result, "audHashes")),
            case["expect"]["audHashes"].to_string(),
            "audHashes case {i}"
        );
        assert_eq!(
            get(&result, "hAudList").as_string().expect("hAudList"),
            case["expect"]["hAudList"].as_str().expect("expected hAudList"),
            "hAudList case {i}"
        );
    }
}

#[wasm_bindgen_test]
fn golden_hashes_match_node() {
    let g = golden();
    for (i, case) in g["hashCases"].as_array().expect("hashCases").iter().enumerate() {
        let result = zkap_zkp_wasm::generate_hash(string_vec(&case["messages"]));
        if let Some(hash) = case["expect"]["hash"].as_str() {
            assert_eq!(result.expect("generateHash"), hash, "hash case {i}");
        } else {
            let err = result.expect_err("expected generateHash error");
            let code = get(&err, "code").as_string().expect("error.code string");
            assert_eq!(code, case["expect"]["errorCode"].as_str().expect("errorCode"), "hash case {i}");
        }
    }
}
