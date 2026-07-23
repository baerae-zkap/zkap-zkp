//! Golden cross-runtime tests for anchor generation and deriveSelector
//! membership over the SAME vectors as
//! packages/sdk-node/__test__/anchor-golden.spec.ts and
//! packages/sdk-wasm/tests/anchor_golden.rs (golden/anchor-vectors.json), so
//! any uniffi/node/wasm divergence — quoting, padding, selector search
//! order, error classification — fails here.

use serde_json::Value;

use crate::{derive_selector, generate_anchor, ZkapCircuitConfig, ZkapError, ZkapSecret};

const GOLDEN: &str = include_str!("../../../golden/anchor-vectors.json");

fn golden() -> Value {
    serde_json::from_str(GOLDEN).expect("parse golden/anchor-vectors.json")
}

fn string_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn config(v: &Value) -> ZkapCircuitConfig {
    let u = |key: &str| v[key].as_u64().unwrap_or_else(|| panic!("config.{key}"));
    ZkapCircuitConfig {
        max_jwt_b64_len: u("maxJwtB64Len"),
        max_payload_b64_len: u("maxPayloadB64Len"),
        max_aud_len: u("maxAudLen"),
        max_exp_len: u("maxExpLen"),
        max_iss_len: u("maxIssLen"),
        max_nonce_len: u("maxNonceLen"),
        max_sub_len: u("maxSubLen"),
        n: u("n"),
        k: u("k"),
        tree_height: u("treeHeight"),
        num_audience_limit: u("numAudienceLimit"),
        claims: string_vec(&v["claims"]),
        forbidden_string: v["forbiddenString"].as_str().expect("forbiddenString").to_string(),
    }
}

fn secrets(v: &Value) -> Vec<ZkapSecret> {
    v.as_array()
        .expect("secrets array")
        .iter()
        .map(|s| ZkapSecret {
            sub: s["sub"].as_str().expect("sub").to_string(),
            iss: s["iss"].as_str().expect("iss").to_string(),
            aud: s["aud"].as_str().expect("aud").to_string(),
        })
        .collect()
}

fn err_message<T>(result: Result<T, ZkapError>) -> String {
    match result {
        Ok(_) => panic!("expected error"),
        Err(ZkapError::ApplicationError { message }) => message,
    }
}

#[test]
fn golden_anchors_match_node() {
    let g = golden();
    let cfg = &g["config3of6"];
    for (name, anchor) in g["anchors"].as_object().expect("anchors object") {
        let result = generate_anchor(config(cfg), secrets(&anchor["secrets6"]))
            .unwrap_or_else(|e| panic!("generateAnchor '{name}' failed: {e:?}"));
        assert_eq!(
            result.evaluations,
            string_vec(&anchor["evaluations"]),
            "anchor '{name}' evaluations diverged from node"
        );
    }
}

#[test]
fn golden_derive_selector_matches_node() {
    let g = golden();
    let cfg = &g["config3of6"];
    for case in g["deriveCases"].as_array().expect("deriveCases array") {
        let name = case["name"].as_str().unwrap_or("?");
        let mut evals =
            string_vec(&g["anchors"][case["anchor"].as_str().expect("anchor name")]["evaluations"]);
        if let Some(n) = case.get("anchorSlice").and_then(Value::as_u64) {
            evals.truncate(n as usize);
        }
        let result = derive_selector(config(cfg), secrets(&case["secrets"]), evals);

        if case["expect"]["selector"].is_array() {
            let selector =
                result.unwrap_or_else(|e| panic!("deriveSelector '{name}' failed: {e:?}"));
            let expected: Vec<u32> = case["expect"]["selector"]
                .as_array()
                .expect("selector array")
                .iter()
                .map(|n| n.as_u64().expect("selector entry") as u32)
                .collect();
            assert_eq!(selector, expected, "selector '{name}' diverged from node");
        } else {
            let includes = case["expect"]["messageIncludes"]
                .as_str()
                .expect("messageIncludes");
            let message = err_message(result);
            assert!(
                message.contains(includes),
                "case '{name}': expected error containing {includes:?}, got {message:?}"
            );
        }
    }
}
