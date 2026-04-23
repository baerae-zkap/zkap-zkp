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

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[napi]
pub fn generate_hash(messages: Vec<String>) -> napi::Result<String> {
    zkap_service::generate_hash(messages).map_err(|e| napi::Error::from_reason(e.to_string()))
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

    // GenerateAnchorResCore { pub anchor: Vec<String> }
    let evaluations = anchor.anchor;
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
    let result = zkap_service::generate_aud_hash(&params, aud_list)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    let aud_hashes = result.individual;
    let h_aud_list = result.combined;
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
    zkap_service::generate_leaf_hash(&params, &iss, &pk_b64)
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

// ---------------------------------------------------------------------------
// Proof feature
// ---------------------------------------------------------------------------

/// Raw proof request passed from JavaScript to `prove`.
#[cfg(feature = "proof")]
#[napi(object)]
pub struct JsProofRequest {
    /// Path to the proving key file on disk.
    pub pk_path: String,
    /// JWT tokens — one per credential (must have exactly `k` entries).
    pub jwts: Vec<String>,
    /// RSA public key moduli in Base64 — one per JWT.
    pub pk_ops: Vec<String>,
    /// Merkle authentication paths — one Vec per JWT.
    pub merkle_paths: Vec<Vec<String>>,
    /// Merkle leaf indices — one per JWT.
    pub leaf_indices: Vec<i64>,
    /// Merkle root as a hex/decimal field-element string.
    pub root: String,
    /// Anchor polynomial evaluations (without hanchor).
    pub anchor_evals: Vec<String>,
    /// Combined anchor hash.
    pub hanchor: String,
    /// Signed UserOperation hash.
    pub h_sign_user_op: String,
    /// Random blinding value.
    pub random: String,
    /// Allowed audience hash values as hex/decimal field-element strings.
    pub aud_hash_list: Vec<String>,
}

/// Output of `prove`: Solidity-compatible proof strings and split public inputs per JWT.
#[cfg(feature = "proof")]
#[napi(object)]
pub struct JsProofOutput {
    /// Solidity-compatible proof strings per proof: [ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy]
    pub proofs: Vec<Vec<String>>,
    /// Public inputs shared across all JWTs (indices 0,1,2,3,6,7) as decimal strings
    pub shared_inputs: Vec<String>,
    /// partial_rhs per JWT (index 5) as decimal string
    pub partial_rhs_list: Vec<String>,
    /// jwt_exp per JWT (index 4) as decimal string
    pub jwt_exp_list: Vec<String>,
}

/// Generate Groth16 proofs from raw user inputs.
///
/// Returns serialized proof bytes and hex-encoded public inputs for each JWT token.
#[cfg(feature = "proof")]
#[napi]
pub fn prove(config: JsCircuitConfig, request: JsProofRequest) -> napi::Result<JsProofOutput> {
    use std::path::PathBuf;
    use zkap_service::RawProofRequest;

    let params = js_config_to_native(config);
    let raw = RawProofRequest::new(
        PathBuf::from(request.pk_path),
        request.jwts,
        request.pk_ops,
        request.merkle_paths,
        request.leaf_indices.into_iter().map(|i| i as u64).collect(),
        request.root,
        request.anchor_evals,
        request.hanchor,
        request.h_sign_user_op,
        request.random,
        request.aud_hash_list,
    );

    let result = zkap_service::prove(&params, raw)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let proofs: Vec<Vec<String>> = result.proofs.iter().map(|p| {
        vec![
            p.a[0].clone(), p.a[1].clone(),
            p.b[0].clone(), p.b[1].clone(), p.b[2].clone(), p.b[3].clone(),
            p.c[0].clone(), p.c[1].clone(),
        ]
    }).collect();
    Ok(JsProofOutput {
        proofs,
        shared_inputs: result.shared_inputs,
        partial_rhs_list: result.verification_rhs_list,
        jwt_exp_list: result.jwt_exp_list,
    })
}

