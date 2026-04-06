#![deny(clippy::all)]

use napi_derive::napi;

/// JS-friendly representation of a JWT credential triple.
#[napi(object)]
pub struct JsSecret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}

/// JS-friendly representation of CircuitConfig.
///
/// All u64 fields are exposed as f64 (JS number) via napi-rs automatic coercion.
/// `claims` is a list of claim name strings; `forbidden_string` is the padding sentinel.
#[napi(object)]
pub struct JsCircuitConfig {
    pub max_jwt_b64_len: f64,
    pub max_payload_b64_len: f64,
    pub max_aud_len: f64,
    pub max_exp_len: f64,
    pub max_iss_len: f64,
    pub max_nonce_len: f64,
    pub max_sub_len: f64,
    pub n: f64,
    pub k: f64,
    pub tree_height: f64,
    pub num_audience_limit: f64,
    pub claims: Vec<String>,
    pub forbidden_string: String,
}

/// Convert `JsCircuitConfig` into the native `CircuitConfig` used by zkap-service.
fn js_config_to_native(c: JsCircuitConfig) -> zkap_service::CircuitConfig {
    use zkap_service::constants::RawCircuitConfig;
    let raw = RawCircuitConfig {
        max_jwt_b64_len: c.max_jwt_b64_len as u64,
        max_payload_b64_len: c.max_payload_b64_len as u64,
        max_aud_len: c.max_aud_len as u64,
        max_exp_len: c.max_exp_len as u64,
        max_iss_len: c.max_iss_len as u64,
        max_nonce_len: c.max_nonce_len as u64,
        max_sub_len: c.max_sub_len as u64,
        n: c.n as u64,
        k: c.k as u64,
        tree_height: c.tree_height as u64,
        num_audience_limit: c.num_audience_limit as u64,
        claims: c.claims,
        forbidden_string: c.forbidden_string,
    };
    raw.into()
}

/// Encode a field element as a 0x-prefixed big-endian hex string.
fn f_to_hex(f: ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[napi]
pub fn generate_hash(messages: Vec<String>) -> napi::Result<String> {
    let f = zkap_service::generate_hash(messages)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(f_to_hex(f))
}

// ---------------------------------------------------------------------------
// generate_anchor
// ---------------------------------------------------------------------------

/// Result of `generate_anchor`: the polynomial evaluation points of the anchor.
#[napi(object)]
pub struct JsAnchorResult {
    /// Each evaluation point of the anchor polynomial, as a 0x-prefixed hex string.
    pub evaluations: Vec<String>,
}

/// Generate a Poseidon threshold anchor from a list of JWT credential secrets.
///
/// Returns the anchor polynomial evaluations as hex strings.
#[napi]
pub fn generate_anchor(
    config: JsCircuitConfig,
    secrets: Vec<JsSecret>,
) -> napi::Result<JsAnchorResult> {
    let params = js_config_to_native(config);
    let secrets: Vec<zkap_service::Secret> = secrets
        .into_iter()
        .map(|s| zkap_service::Secret {
            sub: s.sub,
            iss: s.iss,
            aud: s.aud,
        })
        .collect();

    let anchor = zkap_service::generate_anchor(&params, secrets)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    // PoseidonAnchor<F>(pub Vec<F>)
    let evaluations = anchor.0.into_iter().map(f_to_hex).collect();
    Ok(JsAnchorResult { evaluations })
}

// ---------------------------------------------------------------------------
// generate_aud_hash
// ---------------------------------------------------------------------------

/// Result of `generate_aud_hash`.
#[napi(object)]
pub struct JsAudHashResult {
    /// Per-audience Poseidon hashes, one per slot (including padding), as hex strings.
    pub aud_hashes: Vec<String>,
    /// Combined audience-list hash as a hex string.
    pub h_aud_list: String,
}

/// Compute per-audience hashes and the combined audience-list hash.
#[napi]
pub fn generate_aud_hash(
    config: JsCircuitConfig,
    aud_list: Vec<String>,
) -> napi::Result<JsAudHashResult> {
    let params = js_config_to_native(config);
    let (aud_fields, h_aud_list) = zkap_service::generate_aud_hash(&params, aud_list)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    let aud_hashes = aud_fields.into_iter().map(f_to_hex).collect();
    let h_aud_list = f_to_hex(h_aud_list);
    Ok(JsAudHashResult {
        aud_hashes,
        h_aud_list,
    })
}

// ---------------------------------------------------------------------------
// generate_leaf_hash
// ---------------------------------------------------------------------------

/// Compute the Merkle leaf hash for an issuer + RSA public-key modulus (base64-encoded).
///
/// Returns the leaf field element as a 0x-prefixed hex string.
#[napi]
pub fn generate_leaf_hash(
    config: JsCircuitConfig,
    iss: String,
    pk_b64: String,
) -> napi::Result<String> {
    let params = js_config_to_native(config);
    let f = zkap_service::generate_leaf_hash(&params, &iss, &pk_b64)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(f_to_hex(f))
}

// ---------------------------------------------------------------------------
// Proof feature (skeleton — returns errors until fully implemented)
// ---------------------------------------------------------------------------

#[cfg(feature = "proof")]
#[napi]
pub fn groth16_setup(_config_json: String) -> napi::Result<String> {
    Err(napi::Error::from_reason(
        "groth16_setup: not yet implemented in Node.js bindings",
    ))
}

#[cfg(feature = "proof")]
#[napi]
pub fn prove(_request_json: String) -> napi::Result<String> {
    Err(napi::Error::from_reason(
        "prove: not yet implemented in Node.js bindings",
    ))
}

#[cfg(feature = "proof")]
#[napi]
pub fn verify(_proof_json: String) -> napi::Result<bool> {
    Err(napi::Error::from_reason(
        "verify: not yet implemented in Node.js bindings",
    ))
}
