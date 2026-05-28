#![deny(clippy::all)]

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zkap_service::{
    generate_anchor as service_generate_anchor, generate_audience_hashes, generate_issuer_key_hash,
    generate_poseidon_hash, AnchorSecret, AudienceHashRequest, CircuitConfig,
    GenerateAnchorRequest, HashRequest, IssuerKeyHashRequest,
};

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

fn to_native_config(c: JsCircuitConfig) -> CircuitConfig {
    CircuitConfig {
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
}

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[wasm_bindgen(js_name = generateHash)]
pub fn generate_hash(messages: Vec<String>) -> Result<String, JsValue> {
    let response = generate_poseidon_hash(HashRequest {
        field_elements: messages,
    })
    .map_err(js_err)?;
    Ok(response.hash)
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
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(js_err)?;
    let secrets: Vec<JsSecret> = serde_wasm_bindgen::from_value(secrets).map_err(js_err)?;

    let params = to_native_config(config);
    let native_secrets: Vec<AnchorSecret> = secrets
        .into_iter()
        .map(|s| AnchorSecret {
            subject: s.sub,
            issuer: s.iss,
            audience: s.aud,
        })
        .collect();

    let anchor = service_generate_anchor(
        &params,
        GenerateAnchorRequest {
            secrets: native_secrets,
        },
    )
    .map_err(js_err)?;
    let result = AnchorResult {
        evaluations: anchor.anchor_evaluations,
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
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(js_err)?;
    let params = to_native_config(config);

    let result_core = generate_audience_hashes(
        &params,
        AudienceHashRequest {
            audiences: aud_list,
        },
    )
    .map_err(js_err)?;
    let result = AudHashResult {
        aud_hashes: result_core.audience_hashes,
        h_aud_list: result_core.audience_list_hash,
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
pub fn generate_leaf_hash(config: JsValue, iss: String, pk_b64: String) -> Result<String, JsValue> {
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(js_err)?;
    let params = to_native_config(config);

    let response = generate_issuer_key_hash(
        &params,
        IssuerKeyHashRequest {
            issuer: iss,
            rsa_modulus_b64: pk_b64,
        },
    )
    .map_err(js_err)?;
    Ok(response.hash)
}

// ---------------------------------------------------------------------------
// Unsupported proof functions — clear compile-time errors via type system
// ---------------------------------------------------------------------------

/// `groth16Setup` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-sdk-node` (Node.js) for trusted setup.
#[wasm_bindgen(js_name = groth16Setup)]
pub fn groth16_setup() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "[zkap/sdk-wasm] groth16Setup() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-sdk-node (Node.js) for trusted setup.",
    ))
}

/// `prove` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-sdk-node` for server-side proving, or
/// `@baerae/zkap-zkp-sdk-react-native` for on-device proving.
#[wasm_bindgen(js_name = prove)]
pub fn prove() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "[zkap/sdk-wasm] prove() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-sdk-node (Node.js) for server-side proving, \
         or @baerae/zkap-zkp-sdk-react-native for on-device proving.",
    ))
}

/// `verify` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-sdk-node` for server-side verification.
#[wasm_bindgen(js_name = verify)]
pub fn verify() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "[zkap/sdk-wasm] verify() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-sdk-node (Node.js) for server-side verification.",
    ))
}
