uniffi::setup_scaffolding!();

use std::path::PathBuf;
use zkap_service::constants::RawCircuitConfig;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ZkapError {
    #[error("{message}")]
    ApplicationError { message: String },
}

impl From<zkap_service::error::ApplicationError> for ZkapError {
    fn from(e: zkap_service::error::ApplicationError) -> Self {
        ZkapError::ApplicationError {
            message: e.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapCircuitConfig {
    pub max_jwt_b64_len: u64,
    pub max_payload_b64_len: u64,
    pub max_aud_len: u64,
    pub max_exp_len: u64,
    pub max_iss_len: u64,
    pub max_nonce_len: u64,
    pub max_sub_len: u64,
    pub n: u64,
    pub k: u64,
    pub tree_height: u64,
    pub num_audience_limit: u64,
    pub claims: Vec<String>,
    pub forbidden_string: String,
}

impl From<ZkapCircuitConfig> for zkap_service::CircuitConfig {
    fn from(c: ZkapCircuitConfig) -> Self {
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
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapSecret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapProofRequest {
    pub pk_path: String,
    pub jwts: Vec<String>,
    pub pk_ops: Vec<String>,
    pub merkle_paths: Vec<Vec<String>>,
    pub leaf_indices: Vec<u64>,
    pub root: String,
    pub anchor_evals: Vec<String>,
    pub hanchor: String,
    pub h_sign_user_op: String,
    pub random: String,
    pub aud_hash_list: Vec<String>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapAnchorResult {
    pub evaluations: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapAudHashResult {
    pub aud_hashes: Vec<String>,
    pub h_aud_list: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapProofOutput {
    /// Solidity-compatible proof components per credential: [ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy]
    pub proofs: Vec<Vec<String>>,
    pub shared_inputs: Vec<String>,
    pub partial_rhs_list: Vec<String>,
    pub jwt_exp_list: Vec<String>,
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[uniffi::export]
pub fn generate_hash(messages: Vec<String>) -> Result<String, ZkapError> {
    zkap_service::generate_hash(messages).map_err(ZkapError::from)
}

/// Compute per-audience hashes and the combined audience-list hash.
#[uniffi::export]
pub fn generate_aud_hash(
    config: ZkapCircuitConfig,
    aud_list: Vec<String>,
) -> Result<ZkapAudHashResult, ZkapError> {
    let params = zkap_service::CircuitConfig::from(config);
    let result = zkap_service::generate_aud_hash(&params, aud_list).map_err(ZkapError::from)?;
    Ok(ZkapAudHashResult {
        aud_hashes: result.individual,
        h_aud_list: result.combined,
    })
}

/// Compute the Merkle leaf hash for an issuer + RSA public-key modulus (base64-encoded).
///
/// Returns the leaf field element as a 0x-prefixed hex string.
#[uniffi::export]
pub fn generate_leaf_hash(
    config: ZkapCircuitConfig,
    iss: String,
    pk_b64: String,
) -> Result<String, ZkapError> {
    let params = zkap_service::CircuitConfig::from(config);
    zkap_service::generate_leaf_hash(&params, &iss, &pk_b64).map_err(ZkapError::from)
}

/// Generate a Poseidon threshold anchor from a list of JWT credential secrets.
#[uniffi::export]
pub fn generate_anchor(
    config: ZkapCircuitConfig,
    secrets: Vec<ZkapSecret>,
) -> Result<ZkapAnchorResult, ZkapError> {
    let params = zkap_service::CircuitConfig::from(config);
    let service_secrets = secrets
        .into_iter()
        .map(|s| zkap_service::Secret {
            sub: s.sub,
            iss: s.iss,
            aud: s.aud,
        })
        .collect();
    let result = zkap_service::generate_anchor(&params, service_secrets).map_err(ZkapError::from)?;
    Ok(ZkapAnchorResult {
        evaluations: result.anchor,
    })
}

/// Generate Groth16 proofs from raw user inputs.
#[uniffi::export]
pub fn prove(
    config: ZkapCircuitConfig,
    request: ZkapProofRequest,
) -> Result<ZkapProofOutput, ZkapError> {
    let params = zkap_service::CircuitConfig::from(config);
    let raw = zkap_service::RawProofRequest::new(
        PathBuf::from(request.pk_path),
        request.jwts,
        request.pk_ops,
        request.merkle_paths,
        request.leaf_indices,
        request.root,
        request.anchor_evals,
        request.hanchor,
        request.h_sign_user_op,
        request.random,
        request.aud_hash_list,
    );
    let result = zkap_service::prove(&params, raw).map_err(ZkapError::from)?;
    let proofs: Vec<Vec<String>> = result
        .proofs
        .iter()
        .map(|p| {
            vec![
                p.a[0].clone(),
                p.a[1].clone(),
                p.b[0].clone(),
                p.b[1].clone(),
                p.b[2].clone(),
                p.b[3].clone(),
                p.c[0].clone(),
                p.c[1].clone(),
            ]
        })
        .collect();
    Ok(ZkapProofOutput {
        proofs,
        shared_inputs: result.shared_inputs,
        partial_rhs_list: result.verification_rhs_list,
        jwt_exp_list: result.jwt_exp_list,
    })
}
