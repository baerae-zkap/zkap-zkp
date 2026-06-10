uniffi::setup_scaffolding!();

#[cfg(feature = "wasm-witness")]
use std::path::{Component, Path};

#[cfg(feature = "wasm-witness")]
use ark_serialize::CanonicalDeserialize;
#[cfg(feature = "wasm-witness")]
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
#[cfg(feature = "wasm-witness")]
use sha2::{Digest, Sha256};
#[cfg(feature = "wasm-witness")]
use zkap_service::manifest::Manifest;
#[cfg(feature = "wasm-witness")]
use zkap_service::WitnessBundle;
use zkap_service::{
    generate_anchor as service_generate_anchor, generate_audience_hashes, generate_issuer_key_hash,
    generate_poseidon_hash, AnchorSecret, AudienceHashRequest, CircuitConfig,
    GenerateAnchorRequest, HashRequest, IssuerKeyHashRequest,
};
#[cfg(feature = "wasm-witness")]
use zkap_service::{
    prove_bundles, ArtifactSet, PreflightMode, ProveCredential, ProveRequest, ProveResponse,
};

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

impl From<ZkapCircuitConfig> for CircuitConfig {
    fn from(c: ZkapCircuitConfig) -> Self {
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
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapSecret {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}

/// Per-credential prove inputs (one per JWT participating in the batch).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapProveCredential {
    /// JWT compact serialization (`header.payload.signature`).
    pub jwt: String,
    /// Base64 of the 256-byte RSA-2048 modulus of the issuer key.
    pub rsa_modulus_b64: String,
    /// Merkle authentication path siblings — BN254 Fr hex/decimal.
    pub merkle_path: Vec<String>,
    /// Leaf index in the issuer-key Merkle tree.
    pub merkle_leaf_idx: u64,
}

/// Inputs for [`prove`].
///
/// Replaces the legacy `pk_path` + flat per-credential vectors with
/// the post-migration shape: caller points us at the manifest-validated
/// CRS bundle directory, then supplies the [`crate::ProveRequest`]
/// fields. Hanchor and audience-list hashes are computed internally
/// from `anchor` and the credentials.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapProofRequest {
    /// Directory containing `manifest.json` + the CRS bundle. The
    /// manifest is sha256-validated by `ArtifactSet::load`; witness
    /// generation runs inside the app-supplied `witness_gen.wasm` named by
    /// `witness_gen_path` (verified against `witness_gen_sidecar_path` and
    /// the CRS's `ar1cs_blake3`), no longer read from this CRS bundle.
    /// `ar1cs_prove` always runs natively against the bundled proving key.
    pub manifest_dir: String,
    /// Absolute path to the app-fetched `witness_gen.wasm`, decoupled
    /// from the CRS `manifest_dir`. Verified against `witness_gen_sidecar_path`
    /// and the CRS's `ar1cs_blake3` before use.
    pub witness_gen_path: String,
    /// Absolute path to the app-fetched `witness_gen.json` sidecar for
    /// `witness_gen_path`, decoupled from the CRS `manifest_dir`.
    pub witness_gen_sidecar_path: String,
    /// Randomness salt — BN254 Fr (hex/decimal).
    pub random: String,
    /// Hash of the signed user-op payload — BN254 Fr (hex/decimal).
    pub h_sign_user_op: String,
    /// Anchor polynomial evaluations (length = `config.n - config.k + 1`).
    pub anchor: Vec<String>,
    /// Issuer-key Merkle tree root — BN254 Fr (hex/decimal).
    pub merkle_root: String,
    /// One entry per JWT credential; length must equal `config.k`.
    pub credentials: Vec<ZkapProveCredential>,
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

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapPreparedWitnessInputs {
    pub manifest_dir: String,
    pub wasm_base64: String,
    pub request_json_base64: String,
    pub config_json_base64: String,
    pub witness_gen_sha256: String,
    pub request_json_sha256: String,
    pub config_json_sha256: String,
    pub wasm_byte_length: u64,
    pub request_json_byte_length: u64,
    pub config_json_byte_length: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapWitnessBundleBytes {
    pub witness_bundles_base64: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ZkapWitnessBundleFile {
    pub witness_bundle_path: String,
    pub sha256: String,
    pub byte_length: u64,
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[uniffi::export]
pub fn generate_hash(messages: Vec<String>) -> Result<String, ZkapError> {
    let response = generate_poseidon_hash(HashRequest {
        field_elements: messages,
    })
    .map_err(ZkapError::from)?;
    Ok(response.hash)
}

/// Compute per-audience hashes and the combined audience-list hash.
#[uniffi::export]
pub fn generate_aud_hash(
    config: ZkapCircuitConfig,
    aud_list: Vec<String>,
) -> Result<ZkapAudHashResult, ZkapError> {
    let params = CircuitConfig::from(config);
    let result = generate_audience_hashes(
        &params,
        AudienceHashRequest {
            audiences: aud_list,
        },
    )
    .map_err(ZkapError::from)?;
    Ok(ZkapAudHashResult {
        aud_hashes: result.audience_hashes,
        h_aud_list: result.audience_list_hash,
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
    let params = CircuitConfig::from(config);
    let response = generate_issuer_key_hash(
        &params,
        IssuerKeyHashRequest {
            issuer: iss,
            rsa_modulus_b64: pk_b64,
        },
    )
    .map_err(ZkapError::from)?;
    Ok(response.hash)
}

/// Generate a Poseidon threshold anchor from a list of JWT credential secrets.
#[uniffi::export]
pub fn generate_anchor(
    config: ZkapCircuitConfig,
    secrets: Vec<ZkapSecret>,
) -> Result<ZkapAnchorResult, ZkapError> {
    let params = CircuitConfig::from(config);
    let service_secrets: Vec<AnchorSecret> = secrets
        .into_iter()
        .map(|s| AnchorSecret {
            subject: s.sub,
            issuer: s.iss,
            audience: s.aud,
        })
        .collect();
    let result = service_generate_anchor(
        &params,
        GenerateAnchorRequest {
            secrets: service_secrets,
        },
    )
    .map_err(ZkapError::from)?;
    Ok(ZkapAnchorResult {
        evaluations: result.anchor_evaluations,
    })
}

/// Prepare the manifest-verified inputs required by the iOS WKWebView
/// witness runner. This does not synthesize a witness or generate a proof.
#[uniffi::export]
pub fn prepare_witness_inputs(
    _config: ZkapCircuitConfig,
    request: ZkapProofRequest,
) -> Result<ZkapPreparedWitnessInputs, ZkapError> {
    #[cfg(not(feature = "wasm-witness"))]
    {
        let _ = request;
        return Err(ZkapError::ApplicationError {
            message: "prepare_witness_inputs requires the wasm-witness feature".into(),
        });
    }

    #[cfg(feature = "wasm-witness")]
    {
        let manifest_dir = request.manifest_dir.clone();
        let witness_gen_path = request.witness_gen_path.clone();
        let witness_gen_sidecar_path = request.witness_gen_sidecar_path.clone();
        let (release_config, wasm_bytes) = load_witness_input_artifacts(
            &manifest_dir,
            &witness_gen_path,
            &witness_gen_sidecar_path,
        )?;
        let prove_request = to_service_prove_request(request);
        let request_json =
            serde_json::to_vec(&prove_request).map_err(|e| ZkapError::ApplicationError {
                message: format!("serialize ProveRequest: {e}"),
            })?;
        let config_json =
            serde_json::to_vec(&release_config).map_err(|e| ZkapError::ApplicationError {
                message: format!("serialize CircuitConfig: {e}"),
            })?;

        Ok(ZkapPreparedWitnessInputs {
            manifest_dir,
            wasm_base64: BASE64_STANDARD.encode(&wasm_bytes),
            request_json_base64: BASE64_STANDARD.encode(&request_json),
            config_json_base64: BASE64_STANDARD.encode(&config_json),
            witness_gen_sha256: sha256_hex(&wasm_bytes),
            request_json_sha256: sha256_hex(&request_json),
            config_json_sha256: sha256_hex(&config_json),
            wasm_byte_length: wasm_bytes.len() as u64,
            request_json_byte_length: request_json.len() as u64,
            config_json_byte_length: config_json.len() as u64,
        })
    }
}

/// Generate Groth16 proofs from canonical serialized `Vec<WitnessBundle>`
/// bytes produced outside Rust, e.g. by the iOS WKWebView witness runner.
#[uniffi::export]
pub fn prove_from_witness_bundles(
    _config: ZkapCircuitConfig,
    request: ZkapProofRequest,
    witness: ZkapWitnessBundleBytes,
) -> Result<ZkapProofOutput, ZkapError> {
    #[cfg(not(feature = "wasm-witness"))]
    {
        let _ = request;
        let _ = witness;
        return Err(ZkapError::ApplicationError {
            message: "prove_from_witness_bundles requires the wasm-witness feature".into(),
        });
    }

    #[cfg(feature = "wasm-witness")]
    {
        run_native_worker("zkap-prove-from-witness-bundles", move || {
            let artifact_set = load_artifact_set(&request.manifest_dir)?;
            let bundles = decode_witness_bundles(&witness)?;
            prove_from_witness_bundles_inner(artifact_set, bundles)
        })
    }
}

/// Generate Groth16 proofs from a canonical serialized `Vec<WitnessBundle>`
/// file produced outside Rust. The file is removed after it is read.
#[uniffi::export]
pub fn prove_from_witness_bundle_file(
    _config: ZkapCircuitConfig,
    request: ZkapProofRequest,
    witness: ZkapWitnessBundleFile,
) -> Result<ZkapProofOutput, ZkapError> {
    #[cfg(not(feature = "wasm-witness"))]
    {
        let _ = request;
        let _ = witness;
        return Err(ZkapError::ApplicationError {
            message: "prove_from_witness_bundle_file requires the wasm-witness feature".into(),
        });
    }

    #[cfg(feature = "wasm-witness")]
    {
        run_native_worker("zkap-prove-from-witness-file", move || {
            let bytes = read_and_remove_witness_bundle_file(&witness)?;
            let artifact_set = load_artifact_set(&request.manifest_dir)?;
            let bundles =
                decode_witness_bundle_bytes(&bytes, &witness.sha256, witness.byte_length)?;
            prove_from_witness_bundles_inner(artifact_set, bundles)
        })
    }
}

/// Generate Groth16 proofs.
///
/// Loads the manifest-validated CRS bundle from `request.manifest_dir`,
/// runs witness synthesis inside the release-provided `witness_gen.wasm`,
/// then routes the synthesized bundles through the
/// `zkap_service::prove_bundles(..., PreflightMode::VerifyAfter)` façade
/// against the bundled proving key.
#[uniffi::export]
pub fn prove(
    _config: ZkapCircuitConfig,
    request: ZkapProofRequest,
) -> Result<ZkapProofOutput, ZkapError> {
    #[cfg(not(feature = "wasm-witness"))]
    {
        let _ = request;
        return Err(ZkapError::ApplicationError {
            message: "prove requires the wasm-witness feature and a release witness_gen.wasm"
                .into(),
        });
    }

    #[cfg(feature = "wasm-witness")]
    {
        #[cfg(any(
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        ))]
        {
            let _ = request;
            return Err(ZkapError::ApplicationError {
                message: "native prove() witness synthesis is disabled on iOS-family targets; use the React Native WKWebView witness runner".into(),
            });
        }

        #[cfg(not(any(
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        )))]
        {
            run_native_worker("zkap-prove", move || {
                let artifact_set = load_artifact_set(&request.manifest_dir)?;

                // Capture the CRS + app-supplied witness_gen paths before
                // `to_service_prove_request` consumes `request`.
                let manifest_dir = request.manifest_dir.clone();
                let witness_gen_path = request.witness_gen_path.clone();
                let witness_gen_sidecar_path = request.witness_gen_sidecar_path.clone();
                let prove_request = to_service_prove_request(request);

                // Witness generation uses the app-supplied wasm artifact,
                // gated on the CRS's `ar1cs_blake3`. ar1cs_prove is always
                // native.
                let bundles = {
                    let wasm_bytes = zkap_zkp_prover::load_witness_gen(
                        Path::new(&witness_gen_path),
                        Path::new(&witness_gen_sidecar_path),
                        &read_crs_ar1cs_blake3(&manifest_dir)?,
                    )
                    .map_err(|e| ZkapError::ApplicationError {
                        message: format!("load_witness_gen: {e}"),
                    })?;
                    synthesize_via_wasm(&wasm_bytes, &prove_request, &artifact_set.cfg)?
                };

                prove_from_witness_bundles_inner(artifact_set, bundles)
            })
        }
    }
}

#[cfg(feature = "wasm-witness")]
const NATIVE_WORKER_STACK_SIZE: usize = 32 * 1024 * 1024;

#[cfg(feature = "wasm-witness")]
fn run_native_worker<T, F>(name: &'static str, work: F) -> Result<T, ZkapError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ZkapError> + Send + 'static,
{
    let worker = std::thread::Builder::new()
        .name(name.into())
        .stack_size(NATIVE_WORKER_STACK_SIZE)
        .spawn(work)
        .map_err(|e| ZkapError::ApplicationError {
            message: format!("spawn {name}: {e}"),
        })?;

    worker.join().map_err(|panic| ZkapError::ApplicationError {
        message: format!("native worker {name} panicked: {}", panic_message(&panic)),
    })?
}

#[cfg(feature = "wasm-witness")]
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".into()
    }
}

#[cfg(feature = "wasm-witness")]
fn load_artifact_set(manifest_dir: &str) -> Result<ArtifactSet, ZkapError> {
    let dir = Path::new(manifest_dir);
    let manifest_bytes =
        std::fs::read(dir.join("manifest.json")).map_err(|e| ZkapError::ApplicationError {
            message: format!("read manifest.json: {e}"),
        })?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| ZkapError::ApplicationError {
            message: format!("parse manifest.json: {e}"),
        })?;
    ArtifactSet::load_unsigned(&manifest, dir).map_err(|e| ZkapError::ApplicationError {
        message: format!("ArtifactSet::load_unsigned: {e}"),
    })
}

/// Read the CRS `ar1cs_blake3` from `<manifest_dir>/manifest.json`. Used
/// to gate the app-supplied witness_gen against the CRS shape via
/// `zkap_zkp_prover::load_witness_gen`.
#[cfg(feature = "wasm-witness")]
fn read_crs_ar1cs_blake3(manifest_dir: &str) -> Result<String, ZkapError> {
    let dir = Path::new(manifest_dir);
    let manifest_bytes =
        std::fs::read(dir.join("manifest.json")).map_err(|e| ZkapError::ApplicationError {
            message: format!("read manifest.json: {e}"),
        })?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| ZkapError::ApplicationError {
            message: format!("parse manifest.json: {e}"),
        })?;
    Ok(manifest.ar1cs_blake3)
}

#[cfg(feature = "wasm-witness")]
fn load_witness_input_artifacts(
    manifest_dir: &str,
    witness_gen_path: &str,
    sidecar_path: &str,
) -> Result<(CircuitConfig, Vec<u8>), ZkapError> {
    let dir = Path::new(manifest_dir);
    let manifest_bytes =
        std::fs::read(dir.join("manifest.json")).map_err(|e| ZkapError::ApplicationError {
            message: format!("read manifest.json: {e}"),
        })?;
    let manifest_value: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|e| ZkapError::ApplicationError {
            message: format!("parse manifest.json: {e}"),
        })?;

    let wasm_bytes = zkap_zkp_prover::load_witness_gen(
        Path::new(witness_gen_path),
        Path::new(sidecar_path),
        &read_crs_ar1cs_blake3(manifest_dir)?,
    )
    .map_err(|e| ZkapError::ApplicationError {
        message: format!("load_witness_gen: {e}"),
    })?;
    let config_bytes = read_verified_manifest_artifact(dir, &manifest_value, "circuit_config")?;
    let release_config =
        serde_json::from_slice(&config_bytes).map_err(|e| ZkapError::ApplicationError {
            message: format!("parse config.json: {e}"),
        })?;

    Ok((release_config, wasm_bytes))
}

#[cfg(feature = "wasm-witness")]
fn read_verified_manifest_artifact(
    dir: &Path,
    manifest: &serde_json::Value,
    key: &str,
) -> Result<Vec<u8>, ZkapError> {
    let artifact = manifest
        .get("artifacts")
        .and_then(|artifacts| artifacts.get(key))
        .ok_or_else(|| ZkapError::ApplicationError {
            message: format!("manifest does not provide required {key} artifact"),
        })?;
    let relative_path = artifact
        .get("path")
        .and_then(|path| path.as_str())
        .ok_or_else(|| ZkapError::ApplicationError {
            message: format!("manifest artifact {key} path missing or not a string"),
        })?;
    let expected_sha = artifact
        .get("sha256")
        .and_then(|sha| sha.as_str())
        .ok_or_else(|| ZkapError::ApplicationError {
            message: format!("manifest artifact {key} sha256 missing or not a string"),
        })?;
    let expected_size = artifact.get("size").and_then(|size| size.as_u64());
    let path = safe_manifest_artifact_path(dir, relative_path)?;
    let bytes = std::fs::read(&path).map_err(|e| ZkapError::ApplicationError {
        message: format!("read manifest artifact {key} at {}: {e}", path.display()),
    })?;

    if let Some(expected_size) = expected_size {
        if bytes.len() as u64 != expected_size {
            return Err(ZkapError::ApplicationError {
                message: format!(
                    "manifest artifact {key} size mismatch: expected {} bytes, got {} bytes",
                    expected_size,
                    bytes.len()
                ),
            });
        }
    }

    let actual_sha = sha256_hex(&bytes);
    if !expected_sha.eq_ignore_ascii_case(&actual_sha) {
        return Err(ZkapError::ApplicationError {
            message: format!(
                "manifest artifact {key} sha256 mismatch: expected {}, got {}",
                expected_sha, actual_sha
            ),
        });
    }

    Ok(bytes)
}

#[cfg(feature = "wasm-witness")]
fn safe_manifest_artifact_path(
    dir: &Path,
    relative_path: &str,
) -> Result<std::path::PathBuf, ZkapError> {
    let path = Path::new(relative_path);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ZkapError::ApplicationError {
            message: format!("manifest artifact path must be relative: {relative_path}"),
        });
    }
    Ok(dir.join(path))
}

#[cfg(feature = "wasm-witness")]
fn to_service_prove_request(request: ZkapProofRequest) -> ProveRequest {
    ProveRequest {
        random: request.random,
        h_sign_user_op: request.h_sign_user_op,
        anchor: request.anchor,
        merkle_root: request.merkle_root,
        credentials: request
            .credentials
            .into_iter()
            .map(|c| ProveCredential {
                jwt: c.jwt,
                rsa_modulus_b64: c.rsa_modulus_b64,
                merkle_path: c.merkle_path,
                merkle_leaf_idx: c.merkle_leaf_idx,
            })
            .collect(),
    }
}

#[cfg(feature = "wasm-witness")]
fn decode_witness_bundles(
    witness: &ZkapWitnessBundleBytes,
) -> Result<Vec<WitnessBundle>, ZkapError> {
    let bytes = BASE64_STANDARD
        .decode(witness.witness_bundles_base64.as_bytes())
        .map_err(|e| ZkapError::ApplicationError {
            message: format!("decode witness bundle base64: {e}"),
        })?;
    decode_witness_bundle_bytes(&bytes, &witness.sha256, witness.byte_length)
}

#[cfg(feature = "wasm-witness")]
fn read_and_remove_witness_bundle_file(
    witness: &ZkapWitnessBundleFile,
) -> Result<Vec<u8>, ZkapError> {
    let bytes =
        std::fs::read(&witness.witness_bundle_path).map_err(|e| ZkapError::ApplicationError {
            message: format!("read witness bundle file: {e}"),
        })?;
    let _ = std::fs::remove_file(&witness.witness_bundle_path);
    Ok(bytes)
}

#[cfg(feature = "wasm-witness")]
fn decode_witness_bundle_bytes(
    bytes: &[u8],
    sha256: &str,
    byte_length: u64,
) -> Result<Vec<WitnessBundle>, ZkapError> {
    if bytes.len() as u64 != byte_length {
        return Err(ZkapError::ApplicationError {
            message: format!(
                "witness bundle length mismatch: expected {} bytes, got {} bytes",
                byte_length,
                bytes.len()
            ),
        });
    }

    let expected_sha = sha256.trim().strip_prefix("0x").unwrap_or(sha256.trim());
    if !expected_sha.is_empty() {
        let actual_sha = sha256_hex(bytes);
        if !expected_sha.eq_ignore_ascii_case(&actual_sha) {
            return Err(ZkapError::ApplicationError {
                message: format!(
                    "witness bundle sha256 mismatch: expected {}, got {}",
                    expected_sha, actual_sha
                ),
            });
        }
    }

    Vec::<WitnessBundle>::deserialize_uncompressed(&mut &bytes[..]).map_err(|e| {
        ZkapError::ApplicationError {
            message: format!("WitnessBundle CanonicalDeserialize: {e}"),
        }
    })
}

#[cfg(feature = "wasm-witness")]
fn prove_from_witness_bundles_inner(
    artifact_set: ArtifactSet,
    bundles: Vec<WitnessBundle>,
) -> Result<ZkapProofOutput, ZkapError> {
    // Route the synthesized bundles through the zkap-service façade. The
    // per-bundle rayon parallelism and `ProveResponse` assembly now live
    // inside `prove_bundles`; this crate no longer borrows `pk` /
    // `prepared_arcs` or constructs its own RNG / prove loop.
    let response: ProveResponse =
        prove_bundles(&artifact_set, bundles, PreflightMode::VerifyAfter).map_err(|e| {
            ZkapError::ApplicationError {
                message: format!("prove_bundles: {e}"),
            }
        })?;

    let proofs_serialized: Vec<Vec<String>> = response
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
        proofs: proofs_serialized,
        shared_inputs: vec![
            response.shared_public_inputs.hanchor,
            response.shared_public_inputs.h_a,
            response.shared_public_inputs.root,
            response.shared_public_inputs.h_sign_user_op,
            response.shared_public_inputs.lhs,
            response.shared_public_inputs.h_aud_list,
        ],
        partial_rhs_list: response.verification_rhs,
        jwt_exp_list: response.jwt_exp,
    })
}

#[cfg(feature = "wasm-witness")]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Run `synthesize_witness` inside a wasmi interpreter hosting
/// `witness_gen.wasm`, decode the returned `Vec<WitnessBundle>`.
#[cfg(all(
    feature = "wasmi-diagnostic",
    any(
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
))]
fn synthesize_via_wasm(
    wasm_bytes: &[u8],
    request: &ProveRequest,
    cfg: &zkap_service::CircuitConfig,
) -> Result<Vec<WitnessBundle>, ZkapError> {
    use wasmi::{Engine, Instance, Memory, Module, Store, TypedFunc};

    let wasm_err = |msg: String| ZkapError::ApplicationError { message: msg };

    let engine = Engine::default();
    let module = Module::new(&engine, &mut &wasm_bytes[..])
        .map_err(|e| wasm_err(format!("Module::new: {e}")))?;
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|e| wasm_err(format!("Instance::new: {e}")))?;
    let memory: Memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| wasm_err("wasm export `memory` missing".into()))?;

    let wg_alloc: TypedFunc<u32, u32> = instance
        .get_typed_func(&store, "wg_alloc")
        .map_err(|e| wasm_err(format!("get wg_alloc: {e}")))?;
    let wg_dealloc: TypedFunc<(u32, u32), ()> = instance
        .get_typed_func(&store, "wg_dealloc")
        .map_err(|e| wasm_err(format!("get wg_dealloc: {e}")))?;
    let synth: TypedFunc<(u32, u32, u32, u32), i64> = instance
        .get_typed_func(&store, "synthesize_witness")
        .map_err(|e| wasm_err(format!("get synthesize_witness: {e}")))?;
    let out_ptr_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&store, "wg_last_output_ptr")
        .map_err(|e| wasm_err(format!("get wg_last_output_ptr: {e}")))?;
    let err_ptr_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&store, "wg_last_error_ptr")
        .map_err(|e| wasm_err(format!("get wg_last_error_ptr: {e}")))?;
    let err_len_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&store, "wg_last_error_len")
        .map_err(|e| wasm_err(format!("get wg_last_error_len: {e}")))?;

    let req_json = serde_json::to_vec(request)
        .map_err(|e| wasm_err(format!("serialize ProveRequest: {e}")))?;
    let cfg_json =
        serde_json::to_vec(cfg).map_err(|e| wasm_err(format!("serialize CircuitConfig: {e}")))?;

    let req_ptr = wg_alloc
        .call(&mut store, req_json.len() as u32)
        .map_err(|e| wasm_err(format!("wg_alloc(req): {e}")))?;
    let cfg_ptr = wg_alloc
        .call(&mut store, cfg_json.len() as u32)
        .map_err(|e| wasm_err(format!("wg_alloc(cfg): {e}")))?;

    memory
        .write(&mut store, req_ptr as usize, &req_json)
        .map_err(|e| wasm_err(format!("memory.write(req): {e}")))?;
    memory
        .write(&mut store, cfg_ptr as usize, &cfg_json)
        .map_err(|e| wasm_err(format!("memory.write(cfg): {e}")))?;

    let n = synth
        .call(
            &mut store,
            (
                req_ptr,
                req_json.len() as u32,
                cfg_ptr,
                cfg_json.len() as u32,
            ),
        )
        .map_err(|e| wasm_err(format!("synthesize_witness call: {e}")))?;

    let _ = wg_dealloc.call(&mut store, (req_ptr, req_json.len() as u32));
    let _ = wg_dealloc.call(&mut store, (cfg_ptr, cfg_json.len() as u32));

    if n < 0 {
        let err_ptr = err_ptr_fn
            .call(&mut store, ())
            .map_err(|e| wasm_err(format!("wg_last_error_ptr: {e}")))?;
        let err_len = err_len_fn
            .call(&mut store, ())
            .map_err(|e| wasm_err(format!("wg_last_error_len: {e}")))?;
        let mut buf = vec![0u8; err_len as usize];
        memory
            .read(&store, err_ptr as usize, &mut buf)
            .map_err(|e| wasm_err(format!("memory.read(err): {e}")))?;
        return Err(wasm_err(format!(
            "wasm synthesize_witness reported: {}",
            String::from_utf8_lossy(&buf)
        )));
    }

    let out_ptr = out_ptr_fn
        .call(&mut store, ())
        .map_err(|e| wasm_err(format!("wg_last_output_ptr: {e}")))?;
    let mut out = vec![0u8; n as usize];
    memory
        .read(&store, out_ptr as usize, &mut out)
        .map_err(|e| wasm_err(format!("memory.read(out): {e}")))?;

    let bundles = Vec::<WitnessBundle>::deserialize_uncompressed(&mut &out[..])
        .map_err(|e| wasm_err(format!("WitnessBundle CanonicalDeserialize: {e}")))?;
    Ok(bundles)
}

#[cfg(all(test, feature = "wasm-witness"))]
mod tests {
    use super::*;
    use ark_serialize::CanonicalSerialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_witness_bundle_bytes() -> Vec<u8> {
        let bundles: Vec<WitnessBundle> = Vec::new();
        let mut bytes = Vec::new();
        bundles
            .serialize_uncompressed(&mut bytes)
            .expect("empty witness bundle serialization should succeed");
        bytes
    }

    fn err_message<T>(result: Result<T, ZkapError>) -> String {
        match result {
            Ok(_) => panic!("expected error"),
            Err(ZkapError::ApplicationError { message }) => message,
        }
    }

    fn temp_witness_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "zkap-uniffi-witness-test-{}-{nanos}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn decode_witness_bundle_bytes_accepts_valid_payload() {
        let bytes = empty_witness_bundle_bytes();
        let decoded = decode_witness_bundle_bytes(
            &bytes,
            &format!("0x{}", sha256_hex(&bytes)),
            bytes.len() as u64,
        )
        .expect("valid witness bytes should decode");

        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_witness_bundles_accepts_valid_base64_payload() {
        let bytes = empty_witness_bundle_bytes();
        let decoded = decode_witness_bundles(&ZkapWitnessBundleBytes {
            witness_bundles_base64: BASE64_STANDARD.encode(&bytes),
            sha256: sha256_hex(&bytes),
            byte_length: bytes.len() as u64,
        })
        .expect("valid base64 witness bytes should decode");

        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_witness_bundle_bytes_rejects_length_mismatch() {
        let bytes = empty_witness_bundle_bytes();
        let message = err_message(decode_witness_bundle_bytes(
            &bytes,
            &sha256_hex(&bytes),
            bytes.len() as u64 + 1,
        ));

        assert!(message.contains("witness bundle length mismatch"));
    }

    #[test]
    fn decode_witness_bundle_bytes_rejects_sha_mismatch() {
        let bytes = empty_witness_bundle_bytes();
        let message = err_message(decode_witness_bundle_bytes(
            &bytes,
            &"00".repeat(32),
            bytes.len() as u64,
        ));

        assert!(message.contains("witness bundle sha256 mismatch"));
    }

    #[test]
    fn decode_witness_bundles_rejects_invalid_base64() {
        let message = err_message(decode_witness_bundles(&ZkapWitnessBundleBytes {
            witness_bundles_base64: "not base64".into(),
            sha256: String::new(),
            byte_length: 0,
        }));

        assert!(message.contains("decode witness bundle base64"));
    }

    #[test]
    fn read_and_remove_witness_bundle_file_removes_temp_file() {
        let bytes = empty_witness_bundle_bytes();
        let path = temp_witness_path();
        std::fs::write(&path, &bytes).expect("write witness temp file");

        let read = read_and_remove_witness_bundle_file(&ZkapWitnessBundleFile {
            witness_bundle_path: path.to_string_lossy().into_owned(),
            sha256: sha256_hex(&bytes),
            byte_length: bytes.len() as u64,
        })
        .expect("read witness temp file");

        assert_eq!(read, bytes);
        assert!(!path.exists());
    }
}

/// Run `synthesize_witness` inside a wasmtime instance hosting
/// `witness_gen.wasm`, decode the returned `Vec<WitnessBundle>`.
#[cfg(all(
    feature = "wasm-witness",
    not(any(
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn synthesize_via_wasm(
    wasm_bytes: &[u8],
    request: &ProveRequest,
    cfg: &zkap_service::CircuitConfig,
) -> Result<Vec<WitnessBundle>, ZkapError> {
    use wasmtime::{Engine, Instance, Memory, Module, Store, TypedFunc};

    let wasm_err = |msg: String| ZkapError::ApplicationError { message: msg };

    let engine = Engine::default();
    let module = Module::from_binary(&engine, wasm_bytes)
        .map_err(|e| wasm_err(format!("Module::from_binary: {e}")))?;
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|e| wasm_err(format!("Instance::new: {e}")))?;
    let memory: Memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| wasm_err("wasm export `memory` missing".into()))?;

    let wg_alloc: TypedFunc<u32, u32> = instance
        .get_typed_func(&mut store, "wg_alloc")
        .map_err(|e| wasm_err(format!("get wg_alloc: {e}")))?;
    let wg_dealloc: TypedFunc<(u32, u32), ()> =
        instance
            .get_typed_func(&mut store, "wg_dealloc")
            .map_err(|e| wasm_err(format!("get wg_dealloc: {e}")))?;
    let synth: TypedFunc<(u32, u32, u32, u32), i64> = instance
        .get_typed_func(&mut store, "synthesize_witness")
        .map_err(|e| wasm_err(format!("get synthesize_witness: {e}")))?;
    let out_ptr_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&mut store, "wg_last_output_ptr")
        .map_err(|e| wasm_err(format!("get wg_last_output_ptr: {e}")))?;
    let err_ptr_fn: TypedFunc<(), u32> =
        instance
            .get_typed_func(&mut store, "wg_last_error_ptr")
            .map_err(|e| wasm_err(format!("get wg_last_error_ptr: {e}")))?;
    let err_len_fn: TypedFunc<(), u32> =
        instance
            .get_typed_func(&mut store, "wg_last_error_len")
            .map_err(|e| wasm_err(format!("get wg_last_error_len: {e}")))?;

    let req_json = serde_json::to_vec(request)
        .map_err(|e| wasm_err(format!("serialize ProveRequest: {e}")))?;
    let cfg_json =
        serde_json::to_vec(cfg).map_err(|e| wasm_err(format!("serialize CircuitConfig: {e}")))?;

    let req_ptr = wg_alloc
        .call(&mut store, req_json.len() as u32)
        .map_err(|e| wasm_err(format!("wg_alloc(req): {e}")))?;
    let cfg_ptr = wg_alloc
        .call(&mut store, cfg_json.len() as u32)
        .map_err(|e| wasm_err(format!("wg_alloc(cfg): {e}")))?;

    memory
        .write(&mut store, req_ptr as usize, &req_json)
        .map_err(|e| wasm_err(format!("memory.write(req): {e}")))?;
    memory
        .write(&mut store, cfg_ptr as usize, &cfg_json)
        .map_err(|e| wasm_err(format!("memory.write(cfg): {e}")))?;

    let n = synth
        .call(
            &mut store,
            (
                req_ptr,
                req_json.len() as u32,
                cfg_ptr,
                cfg_json.len() as u32,
            ),
        )
        .map_err(|e| wasm_err(format!("synthesize_witness call: {e}")))?;

    let _ = wg_dealloc.call(&mut store, (req_ptr, req_json.len() as u32));
    let _ = wg_dealloc.call(&mut store, (cfg_ptr, cfg_json.len() as u32));

    if n < 0 {
        let err_ptr = err_ptr_fn
            .call(&mut store, ())
            .map_err(|e| wasm_err(format!("wg_last_error_ptr: {e}")))?;
        let err_len = err_len_fn
            .call(&mut store, ())
            .map_err(|e| wasm_err(format!("wg_last_error_len: {e}")))?;
        let mut buf = vec![0u8; err_len as usize];
        memory
            .read(&store, err_ptr as usize, &mut buf)
            .map_err(|e| wasm_err(format!("memory.read(err): {e}")))?;
        return Err(wasm_err(format!(
            "wasm synthesize_witness reported: {}",
            String::from_utf8_lossy(&buf)
        )));
    }

    let out_ptr = out_ptr_fn
        .call(&mut store, ())
        .map_err(|e| wasm_err(format!("wg_last_output_ptr: {e}")))?;
    let mut out = vec![0u8; n as usize];
    memory
        .read(&store, out_ptr as usize, &mut out)
        .map_err(|e| wasm_err(format!("memory.read(out): {e}")))?;

    let bundles = Vec::<WitnessBundle>::deserialize_uncompressed(&mut &out[..])
        .map_err(|e| wasm_err(format!("WitnessBundle CanonicalDeserialize: {e}")))?;
    Ok(bundles)
}
