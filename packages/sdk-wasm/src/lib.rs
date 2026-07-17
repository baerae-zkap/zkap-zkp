#![deny(clippy::all)]

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zkap_service::error::ApplicationError;
use zkap_service::{
    generate_anchor as service_generate_anchor, generate_audience_hashes, generate_issuer_key_hash,
    generate_poseidon_hash, AnchorSecret, AudienceHashRequest, CircuitConfig,
    GenerateAnchorRequest, HashRequest, IssuerKeyHashRequest,
};

/// Build a real JS `Error` carrying a stable machine-readable `code` property.
///
/// Thrown values used to be raw strings (`JsValue::from_str`); they are now
/// `Error` instances so callers can branch on `error.code` instead of
/// message matching. Message strings are unchanged.
fn coded_err(code: &str, message: &str) -> JsValue {
    let err = js_sys::Error::new(message);
    let _ = js_sys::Reflect::set(&err, &JsValue::from_str("code"), &JsValue::from_str(code));
    err.into()
}

/// Map a zkap-service error to its `error.code` value.
///
/// Mirrors `classify` in packages/sdk-node/src/lib.rs — keep the two in sync
/// (locked by the shared golden tests in golden/anchor-vectors.json).
fn error_code(e: &ApplicationError) -> &'static str {
    match e {
        ApplicationError::AnchorDimensionMismatch { .. } => "DIMENSION_MISMATCH",
        ApplicationError::InvalidFormat(m) if m.contains("No valid selector") => {
            "NO_VALID_SELECTOR"
        }
        ApplicationError::InvalidFormat(m) if m.starts_with("Dimension mismatch") => {
            "DIMENSION_MISMATCH"
        }
        ApplicationError::InvalidFormat(_)
        | ApplicationError::InvalidFieldElement { .. }
        | ApplicationError::AudienceLimitExceeded { .. }
        | ApplicationError::InvalidClaimValue { .. }
        | ApplicationError::InvalidBase64(_)
        | ApplicationError::InvalidRsaModulus(_)
        | ApplicationError::FieldParsingError(_)
        | ApplicationError::TextEncodingError(_)
        | ApplicationError::ParseError(_) => "INVALID_INPUT",
        _ => "GenericFailure",
    }
}

fn app_err(e: ApplicationError) -> JsValue {
    coded_err(error_code(&e), &e.to_string())
}

/// serde-level deserialization failure of a JS argument (config/secrets shape).
fn input_err(e: impl std::fmt::Display) -> JsValue {
    coded_err("INVALID_INPUT", &e.to_string())
}

/// Internal serialization failure building the JS return value.
fn internal_err(e: impl std::fmt::Display) -> JsValue {
    coded_err("GenericFailure", &e.to_string())
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
    .map_err(app_err)?;
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
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(input_err)?;
    let secrets: Vec<JsSecret> = serde_wasm_bindgen::from_value(secrets).map_err(input_err)?;

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
    .map_err(app_err)?;
    let result = AnchorResult {
        evaluations: anchor.anchor_evaluations,
    };
    serde_wasm_bindgen::to_value(&result).map_err(internal_err)
}

// ---------------------------------------------------------------------------
// derive_selector
// ---------------------------------------------------------------------------

/// Derive the k-of-n anchor slot selector (0/1 per slot) from `k` known
/// secrets and the anchor evaluations (hex-or-decimal strings, e.g. from
/// on-chain `getAnchor()`).
///
/// Membership check for shuffled anchors whose dummy-slot preimages were
/// discarded at registration: succeeds iff the presented secrets — in their
/// slot-ascending relative order — occupy some slot combination of the
/// anchor. Errors with "No valid selector found" on mismatch.
#[wasm_bindgen(js_name = deriveSelector, unchecked_return_type = "Array<number>")]
pub fn derive_selector(
    config: JsValue,
    secrets: JsValue,
    anchor_evaluations: Vec<String>,
) -> Result<JsValue, JsValue> {
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(input_err)?;
    let secrets: Vec<JsSecret> = serde_wasm_bindgen::from_value(secrets).map_err(input_err)?;

    let params = to_native_config(config);

    // The rust core reports a wrong-length anchor as an exhausted selector
    // search ("No valid selector found"), which would mis-classify the error
    // — reject the dimension violation up front. Keep this message in sync
    // with packages/sdk-node/src/lib.rs.
    let expected_evals = (params.n - params.k + 1) as usize;
    if anchor_evaluations.len() != expected_evals {
        return Err(coded_err(
            "DIMENSION_MISMATCH",
            &format!(
                "Dimension mismatch: anchor_evaluations length must be n - k + 1 = {expected_evals}, got {}",
                anchor_evaluations.len()
            ),
        ));
    }

    let native_secrets: Vec<AnchorSecret> = secrets
        .into_iter()
        .map(|s| AnchorSecret {
            subject: s.sub,
            issuer: s.iss,
            audience: s.aud,
        })
        .collect();

    let selector = zkap_service::derive_selector(&params, &native_secrets, &anchor_evaluations)
        .map_err(app_err)?;

    let selector: Vec<u32> = selector.into_iter().map(u32::from).collect();
    serde_wasm_bindgen::to_value(&selector).map_err(internal_err)
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
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(input_err)?;
    let params = to_native_config(config);

    let result_core = generate_audience_hashes(
        &params,
        AudienceHashRequest {
            audiences: aud_list,
        },
    )
    .map_err(app_err)?;
    let result = AudHashResult {
        aud_hashes: result_core.audience_hashes,
        h_aud_list: result_core.audience_list_hash,
    };
    serde_wasm_bindgen::to_value(&result).map_err(internal_err)
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
    let config: JsCircuitConfig = serde_wasm_bindgen::from_value(config).map_err(input_err)?;
    let params = to_native_config(config);

    let response = generate_issuer_key_hash(
        &params,
        IssuerKeyHashRequest {
            issuer: iss,
            rsa_modulus_b64: pk_b64,
        },
    )
    .map_err(app_err)?;
    Ok(response.hash)
}

// ---------------------------------------------------------------------------
// Unsupported proof functions — clear compile-time errors via type system
// ---------------------------------------------------------------------------

/// `groth16Setup` is not available in WebAssembly.
///
/// Use `@baerae/zkap-zkp-node` (Node.js) for trusted setup.
#[wasm_bindgen(js_name = groth16Setup)]
pub fn groth16_setup() -> Result<JsValue, JsValue> {
    Err(coded_err(
        "UNSUPPORTED_PLATFORM",
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
    Err(coded_err(
        "UNSUPPORTED_PLATFORM",
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
    Err(coded_err(
        "UNSUPPORTED_PLATFORM",
        "[zkap/sdk-wasm] verify() is not supported in WebAssembly. \
         Use @baerae/zkap-zkp-node (Node.js) for server-side verification.",
    ))
}
