/// WASM integration tests for @baerae/zkap-zkp-wasm hash functions.
///
/// Run with:
///   wasm-pack test --node packages/sdk-wasm
///
/// Fixtures match zkap-circuit/tests/groth16_integration.rs and
/// packages/sdk-node/__test__/hash.spec.ts so all three test suites
/// produce consistent results from the same inputs.
use js_sys::{Array, JSON, Reflect};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// CircuitConfig as a plain JS object (JSON.parse → always plain {}, not Map).
///
/// Using JSON.parse is essential: serde_wasm_bindgen's default Serializer
/// serializes Rust/serde maps as JS Maps, not plain objects, which breaks
/// struct deserialization on the receiving side.
fn default_config() -> JsValue {
    JSON::parse(
        r#"{
            "maxJwtB64Len":     1024,
            "maxPayloadB64Len": 640,
            "maxAudLen":        155,
            "maxExpLen":        20,
            "maxIssLen":        93,
            "maxNonceLen":      93,
            "maxSubLen":        93,
            "n":                6,
            "k":                3,
            "treeHeight":       4,
            "numAudienceLimit": 5,
            "claims":           ["aud", "exp", "iss", "nonce", "sub"],
            "forbiddenString":  "forbidden"
        }"#,
    )
    .expect("JSON.parse for default_config failed")
}

/// n=6 secrets as required by the Vandermonde anchor computation.
fn default_secrets() -> JsValue {
    let entries: Vec<String> = (0..6)
        .map(|i| {
            format!(
                r#"{{"sub":"user-{i}","iss":"https://accounts.example.com","aud":"my-client-id"}}"#
            )
        })
        .collect();
    JSON::parse(&format!("[{}]", entries.join(",")))
        .expect("JSON.parse for default_secrets failed")
}

/// Minimal 2048-bit RSA modulus placeholder (256 × 0xFF bytes, base64-encoded).
fn dummy_pk_b64() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(vec![0xffu8; 256])
}

/// Assert a string matches `0x` + 64 lowercase hex chars (BN254 field element).
fn assert_hex256(s: &str) {
    assert!(s.starts_with("0x"), "Expected 0x prefix, got: {s}");
    let hex = &s[2..];
    assert_eq!(hex.len(), 64, "Expected 64 hex chars, got {} in: {s}", hex.len());
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "Non-hex char in: {s}");
}

/// Get a named string field from a JsValue object.
fn field_str(obj: &JsValue, key: &str) -> String {
    Reflect::get(obj, &JsValue::from_str(key))
        .unwrap()
        .as_string()
        .unwrap_or_else(|| panic!("field '{key}' is not a string"))
}

/// Get a named array field from a JsValue object and collect as Vec<String>.
fn field_str_array(obj: &JsValue, key: &str) -> Vec<String> {
    Array::from(&Reflect::get(obj, &JsValue::from_str(key)).unwrap())
        .iter()
        .map(|v| v.as_string().unwrap_or_else(|| panic!("array element is not a string")))
        .collect()
}

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn generate_hash_single_message_returns_hex256() {
    let result = zkap_zkp_wasm::generate_hash(vec!["12345".to_string()])
        .expect("generate_hash failed");
    assert_hex256(&result);
}

#[wasm_bindgen_test]
fn generate_hash_is_deterministic() {
    let a = zkap_zkp_wasm::generate_hash(vec!["42".to_string(), "99".to_string()]).unwrap();
    let b = zkap_zkp_wasm::generate_hash(vec!["42".to_string(), "99".to_string()]).unwrap();
    assert_eq!(a, b);
}

#[wasm_bindgen_test]
fn generate_hash_different_messages_differ() {
    let a = zkap_zkp_wasm::generate_hash(vec!["1".to_string()]).unwrap();
    let b = zkap_zkp_wasm::generate_hash(vec!["2".to_string()]).unwrap();
    assert_ne!(a, b);
}

#[wasm_bindgen_test]
fn generate_hash_accepts_hex_prefixed_input() {
    let first = zkap_zkp_wasm::generate_hash(vec!["1".to_string()]).unwrap();
    let result = zkap_zkp_wasm::generate_hash(vec![first]).unwrap();
    assert_hex256(&result);
}

#[wasm_bindgen_test]
fn generate_hash_rejects_non_numeric_string() {
    let result = zkap_zkp_wasm::generate_hash(vec!["not-a-field-element".to_string()]);
    assert!(result.is_err(), "Expected error for invalid field element");
}

// ---------------------------------------------------------------------------
// generate_anchor
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn generate_anchor_returns_evaluations_array() {
    let result = zkap_zkp_wasm::generate_anchor(default_config(), default_secrets())
        .expect("generate_anchor failed");
    let evals = field_str_array(&result, "evaluations");
    assert!(!evals.is_empty(), "evaluations should not be empty");
}

#[wasm_bindgen_test]
fn generate_anchor_evaluations_are_hex256() {
    let result = zkap_zkp_wasm::generate_anchor(default_config(), default_secrets()).unwrap();
    for ev in field_str_array(&result, "evaluations") {
        assert_hex256(&ev);
    }
}

#[wasm_bindgen_test]
fn generate_anchor_different_secrets_differ() {
    let alt_entries: Vec<String> = (0..6)
        .map(|i| {
            format!(
                r#"{{"sub":"alt-user-{i}","iss":"https://accounts.example.com","aud":"my-client-id"}}"#
            )
        })
        .collect();
    let secrets_b =
        JSON::parse(&format!("[{}]", alt_entries.join(","))).unwrap();

    let a = zkap_zkp_wasm::generate_anchor(default_config(), default_secrets()).unwrap();
    let b = zkap_zkp_wasm::generate_anchor(default_config(), secrets_b).unwrap();

    assert_ne!(
        field_str_array(&a, "evaluations"),
        field_str_array(&b, "evaluations")
    );
}

#[wasm_bindgen_test]
fn generate_anchor_rejects_wrong_secret_count() {
    let one = JSON::parse(
        r#"[{"sub":"user-0","iss":"https://accounts.example.com","aud":"my-client-id"}]"#,
    )
    .unwrap();
    let result = zkap_zkp_wasm::generate_anchor(default_config(), one);
    assert!(result.is_err(), "Expected error for wrong number of secrets");
}

#[wasm_bindgen_test]
fn generate_anchor_rejects_null_config() {
    let result = zkap_zkp_wasm::generate_anchor(JsValue::NULL, default_secrets());
    assert!(result.is_err(), "Expected error for null config");
}

// ---------------------------------------------------------------------------
// generate_aud_hash
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn generate_aud_hash_returns_aud_hashes_and_h_aud_list() {
    let result =
        zkap_zkp_wasm::generate_aud_hash(default_config(), vec!["my-client-id".to_string()])
            .expect("generate_aud_hash failed");
    let aud_hashes = field_str_array(&result, "audHashes");
    assert!(!aud_hashes.is_empty(), "audHashes should not be empty");
    assert_hex256(&field_str(&result, "hAudList"));
}

#[wasm_bindgen_test]
fn generate_aud_hash_aud_hashes_are_hex256() {
    let result = zkap_zkp_wasm::generate_aud_hash(
        default_config(),
        vec!["aud-1".to_string(), "aud-2".to_string()],
    )
    .unwrap();
    for h in field_str_array(&result, "audHashes") {
        assert_hex256(&h);
    }
}

#[wasm_bindgen_test]
fn generate_aud_hash_length_equals_num_audience_limit() {
    let result =
        zkap_zkp_wasm::generate_aud_hash(default_config(), vec!["aud-1".to_string()]).unwrap();
    // numAudienceLimit = 5 in DEFAULT_CONFIG
    assert_eq!(field_str_array(&result, "audHashes").len(), 5);
}

#[wasm_bindgen_test]
fn generate_aud_hash_different_lists_differ() {
    let a =
        zkap_zkp_wasm::generate_aud_hash(default_config(), vec!["client-a".to_string()]).unwrap();
    let b =
        zkap_zkp_wasm::generate_aud_hash(default_config(), vec!["client-b".to_string()]).unwrap();
    assert_ne!(field_str(&a, "hAudList"), field_str(&b, "hAudList"));
}

#[wasm_bindgen_test]
fn generate_aud_hash_rejects_null_config() {
    let result = zkap_zkp_wasm::generate_aud_hash(JsValue::NULL, vec!["aud".to_string()]);
    assert!(result.is_err(), "Expected error for null config");
}

// ---------------------------------------------------------------------------
// generate_leaf_hash
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn generate_leaf_hash_returns_hex256() {
    let result = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://accounts.example.com".to_string(),
        dummy_pk_b64(),
    )
    .expect("generate_leaf_hash failed");
    assert_hex256(&result);
}

#[wasm_bindgen_test]
fn generate_leaf_hash_is_deterministic() {
    let a = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://accounts.example.com".to_string(),
        dummy_pk_b64(),
    )
    .unwrap();
    let b = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://accounts.example.com".to_string(),
        dummy_pk_b64(),
    )
    .unwrap();
    assert_eq!(a, b);
}

#[wasm_bindgen_test]
fn generate_leaf_hash_different_issuers_differ() {
    let a = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://issuer-a.example.com".to_string(),
        dummy_pk_b64(),
    )
    .unwrap();
    let b = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://issuer-b.example.com".to_string(),
        dummy_pk_b64(),
    )
    .unwrap();
    assert_ne!(a, b);
}

#[wasm_bindgen_test]
fn generate_leaf_hash_different_keys_differ() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let pk_a = STANDARD.encode(vec![0xaau8; 256]);
    let pk_b = STANDARD.encode(vec![0xbbu8; 256]);
    let a = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://accounts.example.com".to_string(),
        pk_a,
    )
    .unwrap();
    let b = zkap_zkp_wasm::generate_leaf_hash(
        default_config(),
        "https://accounts.example.com".to_string(),
        pk_b,
    )
    .unwrap();
    assert_ne!(a, b);
}

#[wasm_bindgen_test]
fn generate_leaf_hash_rejects_null_config() {
    let result = zkap_zkp_wasm::generate_leaf_hash(
        JsValue::NULL,
        "https://accounts.example.com".to_string(),
        dummy_pk_b64(),
    );
    assert!(result.is_err(), "Expected error for null config");
}

// ---------------------------------------------------------------------------
// Unsupported proof functions — must return Err, never panic
// ---------------------------------------------------------------------------

#[wasm_bindgen_test]
fn groth16_setup_returns_unsupported_error() {
    let result = zkap_zkp_wasm::groth16_setup();
    assert!(result.is_err());
    let msg = result.unwrap_err().as_string().unwrap_or_default();
    assert!(msg.contains("groth16Setup"), "Error should mention function name, got: {msg}");
    assert!(msg.contains("not supported"), "Error should say 'not supported', got: {msg}");
}

#[wasm_bindgen_test]
fn prove_returns_unsupported_error() {
    let result = zkap_zkp_wasm::prove();
    assert!(result.is_err());
    let msg = result.unwrap_err().as_string().unwrap_or_default();
    assert!(msg.contains("prove"), "Error should mention function name, got: {msg}");
    assert!(msg.contains("not supported"), "Error should say 'not supported', got: {msg}");
}

#[wasm_bindgen_test]
fn verify_returns_unsupported_error() {
    let result = zkap_zkp_wasm::verify();
    assert!(result.is_err());
    let msg = result.unwrap_err().as_string().unwrap_or_default();
    assert!(msg.contains("verify"), "Error should mention function name, got: {msg}");
    assert!(msg.contains("not supported"), "Error should say 'not supported', got: {msg}");
}
