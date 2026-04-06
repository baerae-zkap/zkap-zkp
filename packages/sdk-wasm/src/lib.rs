#![deny(clippy::all)]

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

fn f_to_hex(f: ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Circuit configuration — mirrors JsCircuitConfig from sdk-node but uses serde for WASM interop.
///
/// JS callers pass a plain object with camelCase keys (e.g. `maxJwtB64Len`), matching the
/// napi-rs convention in sdk-node so both packages accept the same config shape.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsCircuitConfig {
    max_jwt_b64_len: u64,
    max_payload_b64_len: u64,
    max_aud_len: u64,
    max_exp_len: u64,
    max_iss_len: u64,
    max_nonce_len: u64,
    max_sub_len: u64,
    n: u64,
    k: u64,
    tree_height: u64,
    num_audience_limit: u64,
    claims: Vec<String>,
    forbidden_string: String,
}

/// JWT credential secret triple.
#[derive(Deserialize)]
struct JsSecret {
    sub: String,
    iss: String,
    aud: String,
}

/// Output of `generateAnchor`.
#[derive(Serialize)]
struct AnchorResult {
    /// Polynomial evaluation points as 0x-prefixed hex strings.
    evaluations: Vec<String>,
}

/// Output of `generateAudHash`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AudHashResult {
    /// Per-audience Poseidon hashes (including padding slots), as hex strings.
    aud_hashes: Vec<String>,
    /// Combined audience-list hash as a hex string.
    h_aud_list: String,
}

fn to_native_config(c: JsCircuitConfig) -> zkap_service::CircuitConfig {
    use zkap_service::constants::RawCircuitConfig;
    RawCircuitConfig {
        max_jwt_b64_len: c.max_jwt_b64_len,
        max_payload_b64_len: c.max_payload_b64_len,
        max_aud_len: c.max_aud_len,
        max_exp_len: c.max_exp_len,
        max_iss_len: c.max_iss_len,
        max_nonce_len: c.max_nonce_len,
        max_sub_len: c.max_sub_len,
        n: c.n,
        k: c.k,
        tree_height: c.tree_height,
        num_audience_limit: c.num_audience_limit,
        claims: c.claims,
        forbidden_string: c.forbidden_string,
    }
    .into()
}

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[wasm_bindgen(js_name = generateHash)]
pub fn generate_hash(messages: Vec<String>) -> Result<String, JsValue> {
    let f = zkap_service::generate_hash(messages).map_err(js_err)?;
    Ok(f_to_hex(f))
}

// ---------------------------------------------------------------------------
// generate_anchor
// ---------------------------------------------------------------------------

/// Generate a Poseidon threshold anchor from a list of JWT credential secrets.
///
/// `config` — plain JS object matching the `CircuitConfig` shape (camelCase keys).
/// `secrets` — array of `{ sub, iss, aud }` objects.
///
/// Returns `{ evaluations: string[] }`.
#[wasm_bindgen(js_name = generateAnchor)]
pub fn generate_anchor(config: JsValue, secrets: JsValue) -> Result<JsValue, JsValue> {
    let config: JsCircuitConfig =
        serde_wasm_bindgen::from_value(config).map_err(js_err)?;
    let secrets: Vec<JsSecret> =
        serde_wasm_bindgen::from_value(secrets).map_err(js_err)?;

    let params = to_native_config(config);
    let native_secrets: Vec<zkap_service::Secret> = secrets
        .into_iter()
        .map(|s| zkap_service::Secret {
            sub: s.sub,
            iss: s.iss,
            aud: s.aud,
        })
        .collect();

    let anchor = zkap_service::generate_anchor(&params, native_secrets).map_err(js_err)?;
    let result = AnchorResult {
        evaluations: anchor.0.into_iter().map(f_to_hex).collect(),
    };
    serde_wasm_bindgen::to_value(&result).map_err(js_err)
}

// ---------------------------------------------------------------------------
// generate_aud_hash
// ---------------------------------------------------------------------------

/// Compute per-audience hashes and the combined audience-list hash.
///
/// `config` — plain JS object matching the `CircuitConfig` shape (camelCase keys).
/// `audList` — array of audience strings.
///
/// Returns `{ audHashes: string[], hAudList: string }`.
#[wasm_bindgen(js_name = generateAudHash)]
pub fn generate_aud_hash(config: JsValue, aud_list: Vec<String>) -> Result<JsValue, JsValue> {
    let config: JsCircuitConfig =
        serde_wasm_bindgen::from_value(config).map_err(js_err)?;
    let params = to_native_config(config);

    let (aud_fields, h_aud_list) =
        zkap_service::generate_aud_hash(&params, aud_list).map_err(js_err)?;

    let result = AudHashResult {
        aud_hashes: aud_fields.into_iter().map(f_to_hex).collect(),
        h_aud_list: f_to_hex(h_aud_list),
    };
    serde_wasm_bindgen::to_value(&result).map_err(js_err)
}

// ---------------------------------------------------------------------------
// generate_leaf_hash
// ---------------------------------------------------------------------------

/// Compute the Merkle leaf hash for an issuer + RSA public-key modulus (base64-encoded).
///
/// `config` — plain JS object matching the `CircuitConfig` shape (camelCase keys).
///
/// Returns the leaf field element as a 0x-prefixed hex string.
#[wasm_bindgen(js_name = generateLeafHash)]
pub fn generate_leaf_hash(
    config: JsValue,
    iss: String,
    pk_b64: String,
) -> Result<String, JsValue> {
    let config: JsCircuitConfig =
        serde_wasm_bindgen::from_value(config).map_err(js_err)?;
    let params = to_native_config(config);

    let f = zkap_service::generate_leaf_hash(&params, &iss, &pk_b64).map_err(js_err)?;
    Ok(f_to_hex(f))
}

// ---------------------------------------------------------------------------
// Unsupported proof functions — clear compile-time errors via type system
// ---------------------------------------------------------------------------

/// `groth16Setup` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-node` (Node.js) for trusted setup.
#[wasm_bindgen(js_name = groth16Setup)]
pub fn groth16_setup() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "[zkap/sdk-wasm] groth16Setup() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-node (Node.js) for trusted setup.",
    ))
}

/// `prove` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-node` for server-side proving, or
/// `@baerae/zkap-zkp-react-native` for on-device proving.
#[wasm_bindgen(js_name = prove)]
pub fn prove() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "[zkap/sdk-wasm] prove() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-node (Node.js) for server-side proving, \
         or @baerae/zkap-zkp-react-native for on-device proving.",
    ))
}

/// `verify` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-node` for server-side verification.
#[wasm_bindgen(js_name = verify)]
pub fn verify() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "[zkap/sdk-wasm] verify() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-node (Node.js) for server-side verification.",
    ))
}
