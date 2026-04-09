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
// Proof feature
// ---------------------------------------------------------------------------

/// Output of `groth16_setup`: serialized proving key and verifying key bytes.
#[cfg(feature = "proof")]
#[napi(object)]
pub struct JsSetupOutput {
    /// `ark_serialize` bytes of the Groth16 proving key (Node.js Buffer).
    pub pk_bytes: napi::bindgen_prelude::Buffer,
    /// `ark_serialize` bytes of the Groth16 verifying key (Node.js Buffer).
    pub vk_bytes: napi::bindgen_prelude::Buffer,
}

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
    /// Anchor polynomial evaluations plus `hanchor` as the last element.
    pub anchor: Vec<String>,
    /// Signed UserOperation hash.
    pub h_sign_user_op: String,
    /// Random blinding value.
    pub random: String,
    /// Allowed audience values as hex/decimal field-element strings.
    pub aud_list: Vec<String>,
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

#[cfg(feature = "proof")]
fn fp_to_solidity<F: std::fmt::Display + ark_ff::Field>(f: &F) -> String {
    if f.is_zero() { "0".to_string() } else { f.to_string() }
}

#[cfg(feature = "proof")]
fn proof_to_solidity(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> Vec<String> {
    let proof_a = vec![fp_to_solidity(&proof.a.x), fp_to_solidity(&proof.a.y)];
    let proof_b = vec![
        fp_to_solidity(&proof.b.x.c1),
        fp_to_solidity(&proof.b.x.c0),
        fp_to_solidity(&proof.b.y.c1),
        fp_to_solidity(&proof.b.y.c0),
    ];
    let proof_c = vec![fp_to_solidity(&proof.c.x), fp_to_solidity(&proof.c.y)];
    [proof_a, proof_b, proof_c].concat()
}

#[cfg(feature = "proof")]
fn split_public_inputs(
    pub_inputs: Vec<Vec<ark_bn254::Fr>>,
) -> napi::Result<(Vec<String>, Vec<String>, Vec<String>)> {
    const JWT_EXP_INDEX: usize = 4;
    const PARTIAL_RHS_INDEX: usize = 5;
    const SHARED_INDICES: &[usize] = &[0, 1, 2, 3, 6, 7];

    if pub_inputs.is_empty() {
        return Ok((vec![], vec![], vec![]));
    }
    for (row_idx, row) in pub_inputs.iter().enumerate().skip(1) {
        for &idx in SHARED_INDICES {
            if row.get(idx) != pub_inputs[0].get(idx) {
                return Err(napi::Error::from_reason(format!(
                    "shared public input mismatch at index {idx}: JWT[0]={:?} JWT[{row_idx}]={:?}",
                    pub_inputs[0].get(idx).map(|f| f.to_string()),
                    row.get(idx).map(|f| f.to_string()),
                )));
            }
        }
    }
    let jwt_exp_list = pub_inputs.iter()
        .map(|row| row.get(JWT_EXP_INDEX)
            .map(|f| f.to_string())
            .ok_or_else(|| napi::Error::from_reason(
                format!("public input row has fewer than {} elements", JWT_EXP_INDEX + 1)
            )))
        .collect::<napi::Result<Vec<_>>>()?;
    let partial_rhs_list = pub_inputs.iter()
        .map(|row| row.get(PARTIAL_RHS_INDEX)
            .map(|f| f.to_string())
            .ok_or_else(|| napi::Error::from_reason(
                format!("public input row has fewer than {} elements", PARTIAL_RHS_INDEX + 1)
            )))
        .collect::<napi::Result<Vec<_>>>()?;
    let shared_inputs = pub_inputs[0]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != JWT_EXP_INDEX && *i != PARTIAL_RHS_INDEX)
        .map(|(_, f)| f.to_string())
        .collect();
    Ok((shared_inputs, partial_rhs_list, jwt_exp_list))
}

/// Perform a Groth16 trusted setup for the ZKAP circuit.
///
/// Returns serialized proving key and verifying key bytes (ark_serialize format).
/// These bytes can be written to disk and later passed to `prove` / `verify`.
#[cfg(feature = "proof")]
#[napi]
pub fn groth16_setup(config: JsCircuitConfig) -> napi::Result<JsSetupOutput> {
    use ark_serialize::CanonicalSerialize;

    let params = js_config_to_native(config);

    let output = zkap_service::groth16_setup(&params)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    // pk must be serialized uncompressed — ProofGenerator uses load_key_uncompressed.
    let mut pk_bytes = Vec::new();
    output
        .pk
        .serialize_uncompressed(&mut pk_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize pk: {e}")))?;

    let mut vk_bytes = Vec::new();
    output
        .vk
        .serialize_compressed(&mut vk_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize vk: {e}")))?;

    Ok(JsSetupOutput {
        pk_bytes: pk_bytes.into(),
        vk_bytes: vk_bytes.into(),
    })
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
        request.leaf_indices.into_iter().map(|i| i as usize).collect(),
        request.root,
        request.anchor,
        request.h_sign_user_op,
        request.random,
        request.aud_list,
    );

    let (proofs, pub_inputs) = zkap_service::prove(&params, raw)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    let proofs: Vec<Vec<String>> = proofs.iter().map(proof_to_solidity).collect();
    let (shared_inputs, partial_rhs_list, jwt_exp_list) = split_public_inputs(pub_inputs)?;

    Ok(JsProofOutput {
        proofs,
        shared_inputs,
        partial_rhs_list,
        jwt_exp_list,
    })
}

/// Verify a single Groth16 proof.
///
/// - `vk_bytes`: ark_serialize bytes of the verifying key (from `groth16_setup`).
/// - `proof_bytes`: ark_serialize bytes of the proof (from `prove`).
/// - `public_inputs`: field elements as 0x-prefixed hex strings.
///
/// Returns `true` if the proof is valid.
#[cfg(feature = "proof")]
#[napi]
pub fn verify(
    vk_bytes: napi::bindgen_prelude::Buffer,
    proof_bytes: napi::bindgen_prelude::Buffer,
    public_inputs: Vec<String>,
) -> napi::Result<bool> {
    use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key};
    use ark_bn254::Bn254;
    use ark_serialize::CanonicalDeserialize;

    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&*vk_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize vk: {e}")))?;
    let pvk: PreparedVerifyingKey<Bn254> = prepare_verifying_key(&vk);
    let proof = Proof::<Bn254>::deserialize_compressed(&*proof_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize proof: {e}")))?;

    // Parse hex-encoded field elements produced by f_to_hex ("0x" + 64 hex chars).
    let inputs: napi::Result<Vec<ark_bn254::Fr>> = public_inputs
        .iter()
        .map(|s| {
            use ark_ff::PrimeField;
            let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            let bytes = hex::decode(hex_str)
                .map_err(|e| napi::Error::from_reason(format!("Invalid hex input '{s}': {e}")))?;
            Ok(ark_bn254::Fr::from_be_bytes_mod_order(&bytes))
        })
        .collect();

    zkap_service::verify(&pvk, &proof, &inputs?)
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}
