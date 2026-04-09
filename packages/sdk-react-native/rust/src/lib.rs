//! C ABI FFI adapter for @baerae/zkap-zkp-react-native.
//!
//! All functions take and return JSON strings via raw C pointers.
//! Input JSON is owned by the caller; output JSON is heap-allocated here
//! and must be freed by the caller via `zkap_free_string`.
//!
//! Error responses are JSON objects: `{"error": "<message>"}`.
//! Success responses are JSON objects described per function.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use serde::Deserialize;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encode a field element as a 0x-prefixed big-endian hex string.
fn f_to_hex(f: ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

fn fp_to_solidity<F: std::fmt::Display + ark_ff::Field>(f: &F) -> String {
    if f.is_zero() { "0".to_string() } else { f.to_string() }
}

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

#[allow(clippy::type_complexity)]
fn split_public_inputs(
    pub_inputs: Vec<Vec<ark_bn254::Fr>>,
) -> Result<(Vec<String>, Vec<String>, Vec<String>), String> {
    const JWT_EXP_INDEX: usize = 4;
    const PARTIAL_RHS_INDEX: usize = 5;
    const SHARED_INDICES: &[usize] = &[0, 1, 2, 3, 6, 7];

    if pub_inputs.is_empty() {
        return Ok((vec![], vec![], vec![]));
    }
    for (row_idx, row) in pub_inputs.iter().enumerate().skip(1) {
        for &idx in SHARED_INDICES {
            if row.get(idx) != pub_inputs[0].get(idx) {
                return Err(format!(
                    "shared public input mismatch at index {idx}: JWT[0]={:?} JWT[{row_idx}]={:?}",
                    pub_inputs[0].get(idx).map(|f| f.to_string()),
                    row.get(idx).map(|f| f.to_string()),
                ));
            }
        }
    }
    let jwt_exp_list = pub_inputs.iter()
        .map(|row| row.get(JWT_EXP_INDEX)
            .map(|f| f.to_string())
            .ok_or_else(|| format!("row has fewer than {} elements", JWT_EXP_INDEX + 1)))
        .collect::<Result<Vec<_>, _>>()?;
    let partial_rhs_list = pub_inputs.iter()
        .map(|row| row.get(PARTIAL_RHS_INDEX)
            .map(|f| f.to_string())
            .ok_or_else(|| format!("row has fewer than {} elements", PARTIAL_RHS_INDEX + 1)))
        .collect::<Result<Vec<_>, _>>()?;
    let shared_inputs = pub_inputs[0]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != JWT_EXP_INDEX && *i != PARTIAL_RHS_INDEX)
        .map(|(_, f)| f.to_string())
        .collect();
    Ok((shared_inputs, partial_rhs_list, jwt_exp_list))
}

/// Allocate a CString response on the heap and return a raw pointer.
/// The caller is responsible for freeing it with `zkap_free_string`.
fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_else(|_| CString::new("{\"error\":\"null byte in response\"}").unwrap()).into_raw()
}

/// Return a JSON error response as a raw C pointer.
fn error_response(msg: &str) -> *mut c_char {
    let json = serde_json::json!({ "error": msg }).to_string();
    to_c_string(json)
}

/// Parse a raw C string pointer into a Rust &str, returning None on null or invalid UTF-8.
unsafe fn parse_c_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

// ---------------------------------------------------------------------------
// Serde types (mirror of sdk-node structures, JSON-serializable)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RnCircuitConfig {
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

impl From<RnCircuitConfig> for zkap_service::CircuitConfig {
    fn from(c: RnCircuitConfig) -> Self {
        use zkap_service::constants::RawCircuitConfig;
        let raw = RawCircuitConfig {
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
        };
        raw.into()
    }
}

#[derive(Deserialize)]
struct RnSecret {
    sub: String,
    iss: String,
    aud: String,
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/// Free a string previously returned by any zkap_* function.
///
/// # Safety
/// `ptr` must be a pointer returned by a zkap_* function, or null.
#[no_mangle]
pub unsafe extern "C" fn zkap_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------
//
// Input JSON:  { "messages": ["0x...", ...] }
// Output JSON: { "result": "0x..." }

/// Compute a Poseidon hash of one or more field-element strings.
///
/// # Safety
/// `input_json` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn zkap_generate_hash(input_json: *const c_char) -> *mut c_char {
    let json = match parse_c_str(input_json) {
        Some(s) => s,
        None => return error_response("input_json is null or invalid UTF-8"),
    };

    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => return error_response(&format!("JSON parse error: {}", e)),
    };

    let messages: Vec<String> = match serde_json::from_value(v["messages"].clone()) {
        Ok(m) => m,
        Err(e) => return error_response(&format!("messages field error: {}", e)),
    };

    match zkap_service::generate_hash(messages) {
        Ok(f) => to_c_string(serde_json::json!({ "result": f_to_hex(f) }).to_string()),
        Err(e) => error_response(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// generate_anchor
// ---------------------------------------------------------------------------
//
// Input JSON:  { "config": {...}, "secrets": [{"sub":..,"iss":..,"aud":..},...] }
// Output JSON: { "evaluations": ["0x...", ...] }

/// Generate a Poseidon threshold anchor from a list of JWT credential secrets.
///
/// # Safety
/// `input_json` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn zkap_generate_anchor(input_json: *const c_char) -> *mut c_char {
    let json = match parse_c_str(input_json) {
        Some(s) => s,
        None => return error_response("input_json is null or invalid UTF-8"),
    };

    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => return error_response(&format!("JSON parse error: {}", e)),
    };

    let config: RnCircuitConfig = match serde_json::from_value(v["config"].clone()) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("config field error: {}", e)),
    };

    let rn_secrets: Vec<RnSecret> = match serde_json::from_value(v["secrets"].clone()) {
        Ok(s) => s,
        Err(e) => return error_response(&format!("secrets field error: {}", e)),
    };

    let params: zkap_service::CircuitConfig = config.into();
    let secrets: Vec<zkap_service::Secret> = rn_secrets
        .into_iter()
        .map(|s| zkap_service::Secret { sub: s.sub, iss: s.iss, aud: s.aud })
        .collect();

    match zkap_service::generate_anchor(&params, secrets) {
        Ok(anchor) => {
            let evaluations: Vec<String> = anchor.0.into_iter().map(f_to_hex).collect();
            to_c_string(serde_json::json!({ "evaluations": evaluations }).to_string())
        }
        Err(e) => error_response(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// generate_aud_hash
// ---------------------------------------------------------------------------
//
// Input JSON:  { "config": {...}, "aud_list": ["aud1", ...] }
// Output JSON: { "aud_hashes": ["0x...", ...], "h_aud_list": "0x..." }

/// Compute per-audience hashes and the combined audience-list hash.
///
/// # Safety
/// `input_json` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn zkap_generate_aud_hash(input_json: *const c_char) -> *mut c_char {
    let json = match parse_c_str(input_json) {
        Some(s) => s,
        None => return error_response("input_json is null or invalid UTF-8"),
    };

    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => return error_response(&format!("JSON parse error: {}", e)),
    };

    let config: RnCircuitConfig = match serde_json::from_value(v["config"].clone()) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("config field error: {}", e)),
    };

    let aud_list: Vec<String> = match serde_json::from_value(v["aud_list"].clone()) {
        Ok(a) => a,
        Err(e) => return error_response(&format!("aud_list field error: {}", e)),
    };

    let params: zkap_service::CircuitConfig = config.into();

    match zkap_service::generate_aud_hash(&params, aud_list) {
        Ok((aud_fields, h_aud_list)) => {
            let aud_hashes: Vec<String> = aud_fields.into_iter().map(f_to_hex).collect();
            to_c_string(
                serde_json::json!({
                    "aud_hashes": aud_hashes,
                    "h_aud_list": f_to_hex(h_aud_list)
                })
                .to_string(),
            )
        }
        Err(e) => error_response(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// generate_leaf_hash
// ---------------------------------------------------------------------------
//
// Input JSON:  { "config": {...}, "iss": "...", "pk_b64": "..." }
// Output JSON: { "result": "0x..." }

/// Compute the Merkle leaf hash for an issuer and RSA public-key modulus.
///
/// # Safety
/// `input_json` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn zkap_generate_leaf_hash(input_json: *const c_char) -> *mut c_char {
    let json = match parse_c_str(input_json) {
        Some(s) => s,
        None => return error_response("input_json is null or invalid UTF-8"),
    };

    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => return error_response(&format!("JSON parse error: {}", e)),
    };

    let config: RnCircuitConfig = match serde_json::from_value(v["config"].clone()) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("config field error: {}", e)),
    };

    let iss = match v["iss"].as_str() {
        Some(s) => s.to_string(),
        None => return error_response("iss field missing or not a string"),
    };

    let pk_b64 = match v["pk_b64"].as_str() {
        Some(s) => s.to_string(),
        None => return error_response("pk_b64 field missing or not a string"),
    };

    let params: zkap_service::CircuitConfig = config.into();

    match zkap_service::generate_leaf_hash(&params, &iss, &pk_b64) {
        Ok(f) => to_c_string(serde_json::json!({ "result": f_to_hex(f) }).to_string()),
        Err(e) => error_response(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// prove
// ---------------------------------------------------------------------------
//
// Input JSON:  { "config": {...}, "request": { "pk_path": "...", "jwts": [...], ... } }
// Output JSON: { "proofs": ["<hex>", ...], "public_inputs": [["0x...", ...], ...] }

/// Generate Groth16 proofs from raw user inputs.
///
/// # Safety
/// `input_json` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn zkap_prove(input_json: *const c_char) -> *mut c_char {
    use std::path::PathBuf;
    use zkap_service::RawProofRequest;

    let json = match parse_c_str(input_json) {
        Some(s) => s,
        None => return error_response("input_json is null or invalid UTF-8"),
    };

    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => return error_response(&format!("JSON parse error: {}", e)),
    };

    let config: RnCircuitConfig = match serde_json::from_value(v["config"].clone()) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("config field error: {}", e)),
    };

    let req = &v["request"];

    macro_rules! req_str {
        ($field:expr) => {
            match req[$field].as_str() {
                Some(s) => s.to_string(),
                None => return error_response(&format!("request.{} missing or not a string", $field)),
            }
        };
    }

    macro_rules! req_vec_str {
        ($field:expr) => {
            match serde_json::from_value::<Vec<String>>(req[$field].clone()) {
                Ok(v) => v,
                Err(e) => return error_response(&format!("request.{} error: {}", $field, e)),
            }
        };
    }

    let pk_path = req_str!("pk_path");
    let jwts = req_vec_str!("jwts");
    let pk_ops = req_vec_str!("pk_ops");
    let merkle_paths: Vec<Vec<String>> =
        match serde_json::from_value(req["merkle_paths"].clone()) {
            Ok(v) => v,
            Err(e) => return error_response(&format!("request.merkle_paths error: {}", e)),
        };
    let leaf_indices: Vec<usize> = match serde_json::from_value::<Vec<i64>>(req["leaf_indices"].clone()) {
        Ok(v) => v.into_iter().map(|i| i as usize).collect(),
        Err(e) => return error_response(&format!("request.leaf_indices error: {}", e)),
    };
    let root = req_str!("root");
    let anchor = req_vec_str!("anchor");
    let h_sign_user_op = req_str!("h_sign_user_op");
    let random = req_str!("random");
    let aud_list = req_vec_str!("aud_list");

    let params: zkap_service::CircuitConfig = config.into();
    let raw = RawProofRequest::new(
        PathBuf::from(pk_path),
        jwts,
        pk_ops,
        merkle_paths,
        leaf_indices,
        root,
        anchor,
        h_sign_user_op,
        random,
        aud_list,
    );

    match zkap_service::prove(&params, raw) {
        Ok((proofs, pub_inputs)) => {
            let proofs_solidity: Vec<Vec<String>> = proofs.iter().map(proof_to_solidity).collect();
            match split_public_inputs(pub_inputs) {
                Ok((shared_inputs, partial_rhs_list, jwt_exp_list)) => to_c_string(
                    serde_json::json!({
                        "proofs": proofs_solidity,
                        "shared_inputs": shared_inputs,
                        "partial_rhs_list": partial_rhs_list,
                        "jwt_exp_list": jwt_exp_list
                    })
                    .to_string(),
                ),
                Err(e) => error_response(&e),
            }
        }
        Err(e) => error_response(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Android JNI wrappers
//
// Proper JNI entry points for Android. Each wrapper:
//   1. Reads the Java String input
//   2. Calls the C-ABI function (which allocates a Rust heap response)
//   3. Copies the response into a new Java String
//   4. Frees the Rust allocation via zkap_free_string
//   5. Returns the Java String
//
// Method naming (no underscores) avoids JNI name-mangling complexity.
// Kotlin declares: external fun nativeGenerateHash(inputJson: String): String
// JNI symbol:      Java_expo_modules_zkap_ZkapSdkModule_nativeGenerateHash
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod android_jni {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::jstring;

    macro_rules! jni_wrapper {
        ($fn_name:ident, $c_fn:ident) => {
            #[no_mangle]
            pub extern "system" fn $fn_name(
                mut env: JNIEnv,
                _class: JClass,
                input: JString,
            ) -> jstring {
                let input_str: String = match env.get_string(&input) {
                    Ok(s) => s.into(),
                    Err(e) => {
                        let msg = format!("{{\"error\":\"JNI get_string failed: {}\"}}", e);
                        return env.new_string(msg).unwrap().into_raw();
                    }
                };

                let c_input = match std::ffi::CString::new(input_str) {
                    Ok(s) => s,
                    Err(_) => {
                        return env
                            .new_string("{\"error\":\"null byte in input\"}")
                            .unwrap()
                            .into_raw();
                    }
                };

                let result_ptr = unsafe { $c_fn(c_input.as_ptr()) };
                if result_ptr.is_null() {
                    return env
                        .new_string("{\"error\":\"FFI returned null\"}")
                        .unwrap()
                        .into_raw();
                }

                let result_str = unsafe {
                    std::ffi::CStr::from_ptr(result_ptr)
                        .to_string_lossy()
                        .into_owned()
                };
                unsafe { zkap_free_string(result_ptr) };

                env.new_string(result_str).unwrap().into_raw()
            }
        };
    }

    jni_wrapper!(
        Java_expo_modules_zkap_ZkapSdkModule_nativeGenerateHash,
        zkap_generate_hash
    );
    jni_wrapper!(
        Java_expo_modules_zkap_ZkapSdkModule_nativeGenerateAnchor,
        zkap_generate_anchor
    );
    jni_wrapper!(
        Java_expo_modules_zkap_ZkapSdkModule_nativeGenerateAudHash,
        zkap_generate_aud_hash
    );
    jni_wrapper!(
        Java_expo_modules_zkap_ZkapSdkModule_nativeGenerateLeafHash,
        zkap_generate_leaf_hash
    );
    jni_wrapper!(
        Java_expo_modules_zkap_ZkapSdkModule_nativeProve,
        zkap_prove
    );
}
