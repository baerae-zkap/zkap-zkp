#![deny(clippy::all)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::thread;
use std::time::{Duration, Instant};

use ark_ar1cs::{
    prove_with_mode as ar1cs_prove_with_mode, PreflightMode as Ar1csPreflightMode, PreparedArcs,
    ProverError as Ar1csProverError,
};
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;
use napi_derive::napi;
use rayon::prelude::*;
use zkap_service::manifest::Manifest;
use zkap_service::types::F;
use zkap_service::{
    generate_anchor as service_generate_anchor, generate_audience_hashes, generate_issuer_key_hash,
    generate_poseidon_hash, AnchorSecret, ArtifactLoadTiming, ArtifactSet, AudienceHashRequest,
    CircuitConfig, GenerateAnchorRequest, HashRequest, IssuerKeyHashRequest, ProveCredential,
    ProveRequest, ProveResponse, WitnessBundle,
};

const ZKAP_CIRCUIT_COMMIT: &str = "d600a8782f2ae5be89755b3de4dde80473741356";

struct CachedWitnessModule {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
}

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
fn js_config_to_native(c: JsCircuitConfig) -> CircuitConfig {
    CircuitConfig {
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
    }
}

struct CachedProver {
    pk: ProvingKey<Bn254>,
    prepared_arcs: PreparedArcs<F>,
    cfg: CircuitConfig,
    witness_gen_wasm: CachedWitnessModule,
}

struct PreparedArtifactsLoad {
    prepared: Arc<CachedProver>,
    timing: JsPrepareProverTiming,
}

static PROVER_CACHE: OnceLock<Mutex<HashMap<String, Arc<CachedProver>>>> = OnceLock::new();

fn prover_cache() -> &'static Mutex<HashMap<String, Arc<CachedProver>>> {
    PROVER_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn manifest_cache_key(dir: &Path) -> String {
    std::fs::canonicalize(dir)
        .unwrap_or_else(|_| dir.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn get_cached_prover(key: &str) -> Option<Arc<CachedProver>> {
    prover_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(key).cloned())
}

fn load_prepared_artifacts(dir: &Path) -> napi::Result<PreparedArtifactsLoad> {
    let total_start = Instant::now();

    let manifest_start = Instant::now();
    let manifest_bytes = std::fs::read(dir.join("manifest.json"))
        .map_err(|e| napi::Error::from_reason(format!("read manifest.json: {e}")))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| napi::Error::from_reason(format!("parse manifest.json: {e}")))?;
    let manifest_ms = elapsed_ms(manifest_start);

    let artifact_start = Instant::now();
    let (artifact_set, artifact_timing) = ArtifactSet::load_unsigned_with_timing(&manifest, dir)
        .map_err(|e| napi::Error::from_reason(format!("ArtifactSet::load_unsigned: {e}")))?;
    let artifact_load_ms = elapsed_ms(artifact_start);

    let wasm_compile_start = Instant::now();
    let witness_gen_wasm = artifact_set
        .witness_gen_wasm
        .as_deref()
        .map(compile_witness_module)
        .transpose()
        .map_err(napi::Error::from_reason)?
        .ok_or_else(|| {
            napi::Error::from_reason("manifest does not provide required witness_gen.wasm artifact")
        })?;
    let wasm_compile_ms = elapsed_ms(wasm_compile_start);

    let cfg = artifact_set.cfg.clone();
    let prepared_start = Instant::now();
    let pk = artifact_set.pk;
    let prepared_arcs = artifact_set.prepared_arcs;
    let prepared_ms = elapsed_ms(prepared_start);

    Ok(PreparedArtifactsLoad {
        prepared: Arc::new(CachedProver {
            pk,
            prepared_arcs,
            cfg,
            witness_gen_wasm,
        }),
        timing: prepare_timing(
            total_start,
            manifest_ms,
            artifact_load_ms,
            artifact_timing,
            prepared_ms,
            wasm_compile_ms,
        ),
    })
}

fn compile_witness_module(wasm_bytes: &[u8]) -> Result<CachedWitnessModule, String> {
    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::from_binary(&engine, wasm_bytes)
        .map_err(|e| format!("Module::from_binary: {e}"))?;
    Ok(CachedWitnessModule { engine, module })
}

fn prepare_timing(
    total_start: Instant,
    manifest_ms: f64,
    artifact_load_ms: f64,
    artifact_timing: ArtifactLoadTiming,
    prepared_ms: f64,
    wasm_compile_ms: f64,
) -> JsPrepareProverTiming {
    JsPrepareProverTiming {
        total_ms: elapsed_ms(total_start),
        manifest_ms,
        artifact_load_ms,
        ar1cs_ms: artifact_timing.ar1cs_ms,
        pk_ms: artifact_timing.pk_ms,
        vk_ms: artifact_timing.vk_ms,
        pvk_ms: artifact_timing.pvk_ms,
        circuit_config_ms: artifact_timing.circuit_config_ms,
        evm_verifier_ms: artifact_timing.evm_verifier_ms,
        witness_gen_wasm_ms: artifact_timing.witness_gen_wasm_ms,
        prepared_ms,
        wasm_compile_ms,
    }
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn get_or_load_prepared_artifacts(
    dir: &Path,
) -> napi::Result<(Arc<CachedProver>, f64, bool, Option<JsPrepareProverTiming>)> {
    let key = manifest_cache_key(dir);
    if let Some(cached) = get_cached_prover(&key) {
        return Ok((cached, 0.0, true, None));
    }

    let loaded = load_prepared_artifacts(dir)?;
    let load_ms = loaded.timing.total_ms;

    if let Ok(mut cache) = prover_cache().lock() {
        let entry = cache.entry(key).or_insert_with(|| loaded.prepared.clone());
        return Ok((entry.clone(), load_ms, false, Some(loaded.timing)));
    }

    Ok((loaded.prepared, load_ms, false, Some(loaded.timing)))
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    Some(pages.saturating_mul(page_size as u64))
}

#[cfg(target_os = "macos")]
fn current_rss_bytes() -> Option<u64> {
    unsafe {
        let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info_data_t>::uninit();
        let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
        #[allow(deprecated)]
        let task = libc::mach_task_self();
        let result = libc::task_info(
            task,
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr() as libc::task_info_t,
            &mut count,
        );
        if result == libc::KERN_SUCCESS {
            Some(info.assume_init().resident_size)
        } else {
            None
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_rss_bytes() -> Option<u64> {
    None
}

#[derive(Debug, Clone, Copy)]
struct RssStats {
    peak_mb: f64,
    delta_mb: f64,
}

#[derive(Debug)]
struct TimedResult<T> {
    value: T,
    ms: f64,
    rss: Option<RssStats>,
}

fn bytes_to_mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn measure_timed_with_peak_rss<T, E>(
    f: impl FnOnce() -> Result<T, E>,
) -> (Result<T, E>, f64, Option<RssStats>) {
    let baseline = current_rss_bytes();
    let peak = Arc::new(AtomicU64::new(baseline.unwrap_or(0)));
    let running = Arc::new(AtomicBool::new(baseline.is_some()));
    let sampler = baseline.map(|_| {
        let peak = Arc::clone(&peak);
        let running = Arc::clone(&running);
        thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Some(rss) = current_rss_bytes() {
                    peak.fetch_max(rss, Ordering::Relaxed);
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    });

    let start = Instant::now();
    let result = f();
    let ms = elapsed_ms(start);

    if let Some(rss) = current_rss_bytes() {
        peak.fetch_max(rss, Ordering::Relaxed);
    }
    running.store(false, Ordering::Relaxed);
    if let Some(handle) = sampler {
        let _ = handle.join();
    }

    let rss = baseline.map(|base| {
        let peak = peak.load(Ordering::Relaxed);
        RssStats {
            peak_mb: bytes_to_mib(peak),
            delta_mb: bytes_to_mib(peak.saturating_sub(base)),
        }
    });

    (result, ms, rss)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            !(value.is_empty() || value == "0" || value == "false" || value == "no")
        })
        .unwrap_or(false)
}

fn prove_assignments_sequential(
    pk: &ProvingKey<Bn254>,
    prepared_arcs: &PreparedArcs<F>,
    assignments: &[Vec<F>],
) -> Result<Vec<Proof<Bn254>>, Ar1csProverError> {
    let mut rng = OsRng;
    let mut proofs = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        proofs.push(ar1cs_prove_with_mode::<Bn254, _>(
            pk,
            prepared_arcs,
            assignment,
            &mut rng,
            Ar1csPreflightMode::VerifyAfter,
        )?);
    }
    Ok(proofs)
}

fn prove_assignments_parallel(
    pk: &ProvingKey<Bn254>,
    prepared_arcs: &PreparedArcs<F>,
    assignments: &[Vec<F>],
) -> Result<Vec<Proof<Bn254>>, Ar1csProverError> {
    assignments
        .par_iter()
        .map(|assignment| {
            let mut rng = OsRng;
            ar1cs_prove_with_mode::<Bn254, _>(
                pk,
                prepared_arcs,
                assignment,
                &mut rng,
                Ar1csPreflightMode::VerifyAfter,
            )
        })
        .collect()
}

fn measure_proof_run(
    pk: &ProvingKey<Bn254>,
    prepared_arcs: &PreparedArcs<F>,
    assignments: &[Vec<F>],
    parallel: bool,
) -> Result<TimedResult<Vec<Proof<Bn254>>>, Ar1csProverError> {
    let (result, ms, rss) = measure_timed_with_peak_rss(|| {
        if parallel {
            prove_assignments_parallel(pk, prepared_arcs, assignments)
        } else {
            prove_assignments_sequential(pk, prepared_arcs, assignments)
        }
    });
    result.map(|value| TimedResult { value, ms, rss })
}

fn rss_peak_mb(rss: Option<RssStats>) -> Option<f64> {
    rss.map(|stats| stats.peak_mb)
}

fn rss_delta_mb(rss: Option<RssStats>) -> Option<f64> {
    rss.map(|stats| stats.delta_mb)
}

fn max_optional_f64(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn js_proof_request_to_native(request: JsProofRequest) -> ProveRequest {
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
                merkle_leaf_idx: c.merkle_leaf_idx as u64,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// generate_hash
// ---------------------------------------------------------------------------

/// Compute a Poseidon hash of one or more field-element strings (hex or decimal).
///
/// Returns the result as a 0x-prefixed hex string.
#[napi]
pub fn generate_hash(messages: Vec<String>) -> napi::Result<String> {
    let response = generate_poseidon_hash(HashRequest {
        field_elements: messages,
    })
    .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(response.hash)
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
    let secrets: Vec<AnchorSecret> = secrets
        .into_iter()
        .map(|s| AnchorSecret {
            subject: s.sub,
            issuer: s.iss,
            audience: s.aud,
        })
        .collect();

    let anchor = service_generate_anchor(&params, GenerateAnchorRequest { secrets })
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(JsAnchorResult {
        evaluations: anchor.anchor_evaluations,
    })
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
    let result = generate_audience_hashes(
        &params,
        AudienceHashRequest {
            audiences: aud_list,
        },
    )
    .map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(JsAudHashResult {
        aud_hashes: result.audience_hashes,
        h_aud_list: result.audience_list_hash,
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
    let response = generate_issuer_key_hash(
        &params,
        IssuerKeyHashRequest {
            issuer: iss,
            rsa_modulus_b64: pk_b64,
        },
    )
    .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(response.hash)
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Per-credential prove inputs (one entry per JWT in the batch).
#[napi(object)]
pub struct JsProveCredential {
    /// JWT compact serialization (`header.payload.signature`).
    pub jwt: String,
    /// Base64 of the 256-byte RSA-2048 modulus of the issuer key.
    pub rsa_modulus_b64: String,
    /// Merkle authentication path siblings as hex/decimal field-element strings.
    pub merkle_path: Vec<String>,
    /// Merkle leaf index for this credential.
    pub merkle_leaf_idx: f64,
}

/// Inputs for `prove`.
///
/// Replaces the legacy flat per-credential vectors with the post-migration
/// shape: caller points us at the manifest-validated CRS bundle directory,
/// then supplies the `ProveRequest` fields. Hanchor and audience-list hashes
/// are computed internally.
#[napi(object)]
pub struct JsProofRequest {
    /// Directory containing `manifest.json` + the CRS bundle.
    pub manifest_dir: String,
    /// Randomness salt — BN254 Fr (hex/decimal).
    pub random: String,
    /// Hash of the signed user-op payload — BN254 Fr (hex/decimal).
    pub h_sign_user_op: String,
    /// Anchor polynomial evaluations (length = `config.n - config.k + 1`).
    pub anchor: Vec<String>,
    /// Issuer-key Merkle tree root — BN254 Fr (hex/decimal).
    pub merkle_root: String,
    /// One entry per JWT credential; length must equal `config.k`.
    pub credentials: Vec<JsProveCredential>,
}

/// Output of `prove`: Solidity-compatible proof strings and split public inputs per JWT.
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
    /// Phase timing for benchmarking. Wall-clock, nanosecond-source via
    /// `std::time::Instant`.
    pub timing: JsProveTiming,
}

/// Phase-level wall-clock breakdown of a single `prove()` call.
#[napi(object)]
pub struct JsProveTiming {
    /// Wall-clock milliseconds spent reading, hash-checking, and
    /// deserializing the manifest CRS bundle from `manifestDir`.
    pub load_ms: f64,
    /// Wall-clock milliseconds spent in witness generation inside
    /// `witness_gen.wasm`.
    pub synthesize_ms: f64,
    /// Wall-clock milliseconds spent in the selected proof-generation
    /// backend across all `k` credentials.
    pub prove_ms: f64,
    /// Wall-clock milliseconds for the full native `prove()` call,
    /// including load, request conversion, synthesis, proof generation,
    /// and output DTO construction.
    pub total_ms: f64,
    /// `"wasm"` when the release-provided witness generator drove witness
    /// synthesis.
    pub backend: String,
    /// Proof execution mode used for the returned proof set.
    pub proof_mode: String,
    /// Peak process RSS observed during the proof phase, in MiB.
    pub proof_peak_rss_mb: Option<f64>,
    /// Peak process RSS increase over the proof phase baseline, in MiB.
    pub proof_peak_rss_delta_mb: Option<f64>,
    /// Wall-clock milliseconds spent instantiating the cached witness WASM module.
    pub wasm_instantiate_ms: Option<f64>,
    /// Wall-clock milliseconds spent inside the witness WASM call.
    pub wasm_call_ms: Option<f64>,
    /// Wall-clock milliseconds spent deserializing the witness bundles.
    pub witness_deserialize_ms: Option<f64>,
    /// Optional sequential-vs-parallel proof comparison for benchmark runs.
    pub parallel_comparison: Option<JsParallelProveComparison>,
}

/// Sequential-vs-parallel proof timing and peak RSS comparison.
#[napi(object)]
pub struct JsParallelProveComparison {
    /// Sequential proof wall-clock milliseconds.
    pub sequential_prove_ms: f64,
    /// Sequential proof peak process RSS in MiB.
    pub sequential_peak_rss_mb: Option<f64>,
    /// Sequential proof peak process RSS increase in MiB.
    pub sequential_peak_rss_delta_mb: Option<f64>,
    /// Parallel proof wall-clock milliseconds.
    pub parallel_prove_ms: f64,
    /// Parallel proof peak process RSS in MiB.
    pub parallel_peak_rss_mb: Option<f64>,
    /// Parallel proof peak process RSS increase in MiB.
    pub parallel_peak_rss_delta_mb: Option<f64>,
    /// `parallel_prove_ms - sequential_prove_ms`.
    pub prove_ms_delta: f64,
    /// `parallel_peak_rss_mb - sequential_peak_rss_mb`, when both are available.
    pub peak_rss_mb_delta: Option<f64>,
}

/// Detail timing for a cold `prepareProver(manifestDir)` load.
#[napi(object)]
pub struct JsPrepareProverTiming {
    /// Total wall-clock milliseconds spent preparing the cached prover.
    pub total_ms: f64,
    /// Time spent reading and parsing `manifest.json`.
    pub manifest_ms: f64,
    /// Total time spent in `ArtifactSet` loading.
    pub artifact_load_ms: f64,
    /// Time spent loading `circuit.ar1cs`.
    pub ar1cs_ms: f64,
    /// Time spent loading `pk.bin`.
    pub pk_ms: f64,
    /// Time spent loading `vk.bin`.
    pub vk_ms: f64,
    /// Time spent loading `pvk.bin`.
    pub pvk_ms: f64,
    /// Time spent loading `config.json`.
    pub circuit_config_ms: f64,
    /// Time spent checking the optional EVM verifier artifact.
    pub evm_verifier_ms: f64,
    /// Time spent loading `witness_gen.wasm`.
    pub witness_gen_wasm_ms: f64,
    /// Time spent moving artifacts into the cached prepared proving state.
    pub prepared_ms: f64,
    /// Time spent compiling `witness_gen.wasm` into a cached wasmtime module.
    pub wasm_compile_ms: f64,
}

/// Result of `prepareProver(manifestDir)`.
#[napi(object)]
pub struct JsPrepareProverResult {
    /// Wall-clock milliseconds spent loading and preparing the prover.
    /// `0` when the manifest directory was already cached in this process.
    pub load_ms: f64,
    /// `true` when the prepared prover came from the process-local cache.
    pub cached: bool,
    /// Detail timing when this call performed a cold load.
    pub timing: Option<JsPrepareProverTiming>,
}

/// Preload and cache the manifest-backed proving artifacts for later
/// `prove()` calls in the same Node.js process.
#[napi]
pub fn prepare_prover(manifest_dir: String) -> napi::Result<JsPrepareProverResult> {
    let dir = Path::new(&manifest_dir);
    let (_prepared, load_ms, cached, timing) = get_or_load_prepared_artifacts(dir)?;
    Ok(JsPrepareProverResult {
        load_ms,
        cached,
        timing,
    })
}

fn proof_output_from_response(result: ProveResponse, timing: JsProveTiming) -> JsProofOutput {
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

    JsProofOutput {
        proofs,
        shared_inputs: vec![
            result.shared_public_inputs.hanchor,
            result.shared_public_inputs.h_a,
            result.shared_public_inputs.root,
            result.shared_public_inputs.h_sign_user_op,
            result.shared_public_inputs.lhs,
            result.shared_public_inputs.h_aud_list,
        ],
        partial_rhs_list: result.verification_rhs,
        jwt_exp_list: result.jwt_exp,
        timing,
    }
}

/// Generate Groth16 proofs.
///
/// Loads the manifest-validated CRS bundle from `request.manifest_dir`,
/// runs witness synthesis inside the release-provided `witness_gen.wasm`,
/// then runs the circuit-agnostic
/// `ark_ar1cs::prove_with_mode(..., VerifyAfter)` against the bundled
/// proving key and prepared matrices.
#[napi]
pub fn prove(_config: JsCircuitConfig, request: JsProofRequest) -> napi::Result<JsProofOutput> {
    let total_start = Instant::now();
    let dir = Path::new(&request.manifest_dir);
    let (prepared, load_ms, _cached, _load_timing) = get_or_load_prepared_artifacts(dir)?;

    let prove_request = js_proof_request_to_native(request);

    let synth_start = Instant::now();
    let output = synthesize_via_wasm(&prepared.witness_gen_wasm, &prove_request, &prepared.cfg)
        .map_err(napi::Error::from_reason)?;
    let (bundles, backend, wasm_timing) = (output.bundles, "wasm", Some(output.timing));
    let synthesize_ms = elapsed_ms(synth_start);

    // Split each bundle into (full_assignment, public_inputs) before
    // proof generation so public inputs can be returned alongside the
    // `ark_ar1cs` proofs.
    let mut public_inputs: Vec<Vec<F>> = Vec::with_capacity(bundles.len());
    let mut assignments: Vec<Vec<F>> = Vec::with_capacity(bundles.len());
    for bundle in bundles {
        public_inputs.push(bundle.public_inputs);
        assignments.push(bundle.full_assignment);
    }

    let compare_parallel = env_flag("COMPARE_PARALLEL_PROVE");
    let use_parallel = env_flag("ZKAP_PROVE_PARALLEL");
    let prove_phase_start = Instant::now();
    let (proofs_out, proof_mode, proof_peak_rss_mb, proof_peak_rss_delta_mb, parallel_comparison) =
        if compare_parallel {
            let sequential =
                measure_proof_run(&prepared.pk, &prepared.prepared_arcs, &assignments, false)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("ark_ar1cs sequential prove: {e}"))
                    })?;
            let parallel =
                measure_proof_run(&prepared.pk, &prepared.prepared_arcs, &assignments, true)
                    .map_err(|e| {
                        napi::Error::from_reason(format!("ark_ar1cs parallel prove: {e}"))
                    })?;
            let sequential_peak = rss_peak_mb(sequential.rss);
            let parallel_peak = rss_peak_mb(parallel.rss);
            let comparison = JsParallelProveComparison {
                sequential_prove_ms: sequential.ms,
                sequential_peak_rss_mb: sequential_peak,
                sequential_peak_rss_delta_mb: rss_delta_mb(sequential.rss),
                parallel_prove_ms: parallel.ms,
                parallel_peak_rss_mb: parallel_peak,
                parallel_peak_rss_delta_mb: rss_delta_mb(parallel.rss),
                prove_ms_delta: parallel.ms - sequential.ms,
                peak_rss_mb_delta: match (sequential_peak, parallel_peak) {
                    (Some(seq), Some(par)) => Some(par - seq),
                    _ => None,
                },
            };
            (
                sequential.value,
                "compare-sequential-submit".to_string(),
                max_optional_f64(sequential_peak, parallel_peak),
                max_optional_f64(rss_delta_mb(sequential.rss), rss_delta_mb(parallel.rss)),
                Some(comparison),
            )
        } else {
            let proof_run = measure_proof_run(
                &prepared.pk,
                &prepared.prepared_arcs,
                &assignments,
                use_parallel,
            )
            .map_err(|e| napi::Error::from_reason(format!("ark_ar1cs prove: {e}")))?;
            (
                proof_run.value,
                if use_parallel {
                    "parallel".to_string()
                } else {
                    "sequential".to_string()
                },
                rss_peak_mb(proof_run.rss),
                rss_delta_mb(proof_run.rss),
                None,
            )
        };
    let prove_ms = elapsed_ms(prove_phase_start);
    let result: ProveResponse = (proofs_out, public_inputs).into();

    let total_ms = elapsed_ms(total_start);
    Ok(proof_output_from_response(
        result,
        JsProveTiming {
            load_ms,
            synthesize_ms,
            prove_ms,
            total_ms,
            backend: backend.to_string(),
            proof_mode,
            proof_peak_rss_mb,
            proof_peak_rss_delta_mb,
            wasm_instantiate_ms: wasm_timing.as_ref().map(|timing| timing.instantiate_ms),
            wasm_call_ms: wasm_timing.as_ref().map(|timing| timing.call_ms),
            witness_deserialize_ms: wasm_timing.as_ref().map(|timing| timing.deserialize_ms),
            parallel_comparison,
        },
    ))
}

// ---------------------------------------------------------------------------
// loadRelease
// ---------------------------------------------------------------------------

/// Inputs for `loadRelease`.
#[napi(object)]
pub struct JsLoadReleaseOpts {
    /// Absolute path to the directory containing zkap-circuit's flat
    /// prefixed release bundle (e.g. `1-of-1-pk.bin`, `1-of-1-manifest.json`,
    /// `1-of-1-SHA256SUMS`, `witness_gen.wasm`, …).
    pub release_dir: String,
    /// Shape of the release to stage. Must be `"1-of-1"` or `"3-of-3"`.
    pub shape: String,
    /// Optional expected `manifest.build.circuit_commit`.
    ///
    /// Defaults to the zkap-circuit revision this SDK was built against. Full
    /// 40-character commits and unambiguous prefixes of at least 7 characters
    /// are accepted.
    pub expected_circuit_commit: Option<String>,
    /// Skip `manifest.build.circuit_commit` validation. Intended only for
    /// local development bundles that are known to be compatible.
    pub allow_circuit_commit_mismatch: Option<bool>,
}

/// Result of `loadRelease`.
///
/// The richer return shape lets `node-harness` learn `circuit_id`,
/// `public_input_names`, and `setup_provenance` directly from
/// `manifestJson` without re-opening the on-disk manifest.
#[napi(object)]
pub struct JsLoadReleaseResult {
    /// Absolute path to the unprefixed staged bundle directory. Pass
    /// this as `manifest_dir` to `prove()` / `verify()`.
    pub staged_dir: String,
    /// Raw per-shape manifest.json text (already SHA-verified by the
    /// loader). Parse with `JSON.parse` on the JS side.
    pub manifest_json: String,
    /// Echoed shape post-validation (`"1-of-1"` / `"3-of-3"`).
    pub shape: String,
    /// First 16 hex of SHA256 of the per-shape `<shape>-SHA256SUMS`
    /// (cache key). Stable across re-bakes of the same release.
    pub release_sha: String,
}

/// Convert zkap-circuit's flat prefixed release bundle into a
/// SHA-verified unprefixed staged directory under `os.tmpdir()`.
///
/// Idempotent: a second call with the same `{ releaseDir, shape }`
/// returns the same `stagedDir` (sub-second warm-cache re-verify).
/// Concurrent calls coordinate via an `fs2` exclusive advisory lock.
///
/// Errors surface as `napi::Error` whose message starts with
/// `loadRelease:` followed by the underlying `ReleaseError` display
/// (e.g. `loadRelease: release artifact pk.bin: expected <a>, got <b>`).
#[napi]
pub fn load_release(opts: JsLoadReleaseOpts) -> napi::Result<JsLoadReleaseResult> {
    let loaded = zkap_zkp_prover::load_release(Path::new(&opts.release_dir), &opts.shape)
        .map_err(|e| napi::Error::from_reason(format!("loadRelease: {e}")))?;
    validate_manifest_circuit_commit(
        &loaded.manifest_json,
        opts.expected_circuit_commit.as_deref(),
        opts.allow_circuit_commit_mismatch.unwrap_or(false),
    )?;
    Ok(JsLoadReleaseResult {
        staged_dir: loaded.staged_dir.to_string_lossy().into_owned(),
        manifest_json: loaded.manifest_json,
        shape: loaded.shape,
        release_sha: loaded.release_sha,
    })
}

fn normalize_git_commit_prefix(value: &str, field: &str) -> napi::Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let valid_len = (7..=40).contains(&normalized.len());
    let valid_hex = normalized.chars().all(|c| c.is_ascii_hexdigit());
    if !valid_len || !valid_hex {
        return Err(napi::Error::from_reason(format!(
            "loadRelease: invalid {field}: expected a 7-40 character git commit hex prefix"
        )));
    }
    Ok(normalized)
}

fn validate_manifest_circuit_commit(
    manifest_json: &str,
    expected_override: Option<&str>,
    allow_mismatch: bool,
) -> napi::Result<()> {
    if allow_mismatch {
        return Ok(());
    }

    let expected = normalize_git_commit_prefix(
        expected_override.unwrap_or(ZKAP_CIRCUIT_COMMIT),
        "expectedCircuitCommit",
    )?;
    let manifest: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|e| napi::Error::from_reason(format!("loadRelease: parse manifest.json: {e}")))?;
    let actual_raw = manifest
        .get("build")
        .and_then(|build| build.get("circuit_commit"))
        .and_then(|commit| commit.as_str())
        .ok_or_else(|| {
            napi::Error::from_reason(format!(
                "loadRelease: incompatible zkap-circuit release: release manifest missing build.circuit_commit. Use a release built from zkap-circuit {expected}."
            ))
        })?;
    let actual = normalize_git_commit_prefix(actual_raw, "release manifest build.circuit_commit")?;
    if !actual.starts_with(&expected) {
        return Err(napi::Error::from_reason(format!(
            "loadRelease: zkap-circuit release commit mismatch: expected {expected}, got {actual}. Use a release built from the zkap-circuit revision compatible with this SDK."
        )));
    }
    Ok(())
}

/// Per-proof verification verdict returned by `verify`.
#[napi(object)]
pub struct JsVerifyOutput {
    /// One boolean per proof in `proofOutput.proofs`, in order:
    /// `true` if `Groth16::verify_proof(&pvk, proofs[i], pub_inputs[i])`
    /// returned `Ok(true)`, otherwise `false` (verification rejected,
    /// or pairing returned a downstream error which we treat as
    /// `false` — the proof did not verify against this verifier).
    pub results: Vec<bool>,
    /// Aggregate convenience flag: `results.iter().all(|x| *x)`.
    pub all_valid: bool,
}

/// Verify a batch of proofs produced by `prove` against the
/// `PreparedVerifyingKey` registered in `manifestDir`'s
/// `manifest.json` (`pvk.bin`). The function does no synthesize work;
/// it parses the Solidity-shaped `proofs[i]` (8 hex field strings,
/// layout `[ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy]`), recomposes
/// the canonical 8-element public-input vector
/// `[hanchor, h_a, root, h_sign_user_op, jwt_exp[i], partial_rhs[i],
///   lhs, h_aud_list]` from `proofOutput`, and runs
/// `ark_groth16::Groth16::<Bn254>::verify_proof` against `pvk` for
/// every entry.
///
/// `manifestDir` is the same path used by `prove`. The manifest
/// SHA gate (`ArtifactSet::load`) is re-applied so a bundle that
/// was tampered with after prove() still fails here.
#[napi]
pub fn verify(manifest_dir: String, proof_output: JsProofOutput) -> napi::Result<JsVerifyOutput> {
    let dir = Path::new(&manifest_dir);
    let manifest_bytes = std::fs::read(dir.join("manifest.json"))
        .map_err(|e| napi::Error::from_reason(format!("read manifest.json: {e}")))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| napi::Error::from_reason(format!("parse manifest.json: {e}")))?;
    let artifact_set = ArtifactSet::load_unsigned(&manifest, dir)
        .map_err(|e| napi::Error::from_reason(format!("ArtifactSet::load_unsigned: {e}")))?;

    let k = proof_output.proofs.len();
    if proof_output.partial_rhs_list.len() != k || proof_output.jwt_exp_list.len() != k {
        return Err(napi::Error::from_reason(format!(
            "proof_output shape mismatch: proofs.len()={k}, partial_rhs_list.len()={}, jwt_exp_list.len()={}",
            proof_output.partial_rhs_list.len(),
            proof_output.jwt_exp_list.len(),
        )));
    }
    if proof_output.shared_inputs.len() != 6 {
        return Err(napi::Error::from_reason(format!(
            "proof_output.shared_inputs must have 6 entries, got {}",
            proof_output.shared_inputs.len()
        )));
    }

    let mut results = Vec::with_capacity(k);
    for i in 0..k {
        let proof = parse_proof_strings(&proof_output.proofs[i])
            .map_err(|e| napi::Error::from_reason(format!("parse proofs[{i}]: {e}")))?;
        let pub_inputs = canonical_public_inputs(
            &proof_output.shared_inputs,
            &proof_output.jwt_exp_list[i],
            &proof_output.partial_rhs_list[i],
        )
        .map_err(|e| napi::Error::from_reason(format!("parse public_inputs[{i}]: {e}")))?;

        let ok =
            Groth16::<Bn254>::verify_proof(&artifact_set.pvk, &proof, &pub_inputs).unwrap_or(false);
        results.push(ok);
    }

    let all_valid = results.iter().all(|x| *x);
    Ok(JsVerifyOutput { results, all_valid })
}

fn fq_from_hex(s: &str) -> Result<Fq, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|e| format!("hex decode {s:?}: {e}"))?;
    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

fn fr_from_hex(s: &str) -> Result<F, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|e| format!("hex decode {s:?}: {e}"))?;
    Ok(F::from_be_bytes_mod_order(&bytes))
}

fn parse_proof_strings(p: &[String]) -> Result<Proof<Bn254>, String> {
    if p.len() != 8 {
        return Err(format!("proof must have 8 field elements, got {}", p.len()));
    }
    // Layout (from JsProofOutput build site): [a0, a1, b0, b1, b2, b3, c0, c1]
    // where b is [b.x.c1, b.x.c0, b.y.c1, b.y.c0] — matches the Solidity
    // verifier's pairing-friendly ordering. Recompose Fq2's via
    // `Fq2::new(c0, c1)`.
    let a = G1Affine::new_unchecked(fq_from_hex(&p[0])?, fq_from_hex(&p[1])?);
    let bx = Fq2::new(fq_from_hex(&p[3])?, fq_from_hex(&p[2])?);
    let by = Fq2::new(fq_from_hex(&p[5])?, fq_from_hex(&p[4])?);
    let b = G2Affine::new_unchecked(bx, by);
    let c = G1Affine::new_unchecked(fq_from_hex(&p[6])?, fq_from_hex(&p[7])?);
    Ok(Proof { a, b, c })
}

fn canonical_public_inputs(
    shared: &[String],
    jwt_exp: &str,
    partial_rhs: &str,
) -> Result<Vec<F>, String> {
    // Shared layout in JsProofOutput.shared_inputs:
    //   [hanchor(0), h_a(1), root(2), h_sign_user_op(3), lhs(4), h_aud_list(5)]
    // Canonical 8-element instance layout per `ProveResponse::public_inputs_for`:
    //   [hanchor, h_a, root, h_sign_user_op, jwt_exp[i], partial_rhs[i], lhs, h_aud_list]
    Ok(vec![
        fr_from_hex(&shared[0])?,
        fr_from_hex(&shared[1])?,
        fr_from_hex(&shared[2])?,
        fr_from_hex(&shared[3])?,
        fr_from_hex(jwt_exp)?,
        fr_from_hex(partial_rhs)?,
        fr_from_hex(&shared[4])?,
        fr_from_hex(&shared[5])?,
    ])
}

/// Run `synthesize_witness` inside a wasmtime instance hosting
/// `witness_gen.wasm`, decode the returned `Vec<WitnessBundle>`.
struct WasmSynthesizeOutput {
    bundles: Vec<WitnessBundle>,
    timing: WasmSynthesizeTiming,
}

struct WasmSynthesizeTiming {
    instantiate_ms: f64,
    call_ms: f64,
    deserialize_ms: f64,
}

fn synthesize_via_wasm(
    witness_module: &CachedWitnessModule,
    request: &ProveRequest,
    cfg: &CircuitConfig,
) -> Result<WasmSynthesizeOutput, String> {
    use wasmtime::{Instance, Memory, Store, TypedFunc};

    let instantiate_start = Instant::now();
    let mut store = Store::new(&witness_module.engine, ());
    let instance = Instance::new(&mut store, &witness_module.module, &[])
        .map_err(|e| format!("Instance::new: {e}"))?;
    let memory: Memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| "wasm export `memory` missing".to_string())?;

    let wg_alloc: TypedFunc<u32, u32> = instance
        .get_typed_func(&mut store, "wg_alloc")
        .map_err(|e| format!("get wg_alloc: {e}"))?;
    let wg_dealloc: TypedFunc<(u32, u32), ()> = instance
        .get_typed_func(&mut store, "wg_dealloc")
        .map_err(|e| format!("get wg_dealloc: {e}"))?;
    let synth: TypedFunc<(u32, u32, u32, u32), i64> = instance
        .get_typed_func(&mut store, "synthesize_witness")
        .map_err(|e| format!("get synthesize_witness: {e}"))?;
    let out_ptr_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&mut store, "wg_last_output_ptr")
        .map_err(|e| format!("get wg_last_output_ptr: {e}"))?;
    let err_ptr_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&mut store, "wg_last_error_ptr")
        .map_err(|e| format!("get wg_last_error_ptr: {e}"))?;
    let err_len_fn: TypedFunc<(), u32> = instance
        .get_typed_func(&mut store, "wg_last_error_len")
        .map_err(|e| format!("get wg_last_error_len: {e}"))?;
    let instantiate_ms = elapsed_ms(instantiate_start);

    let req_json =
        serde_json::to_vec(request).map_err(|e| format!("serialize ProveRequest: {e}"))?;
    let cfg_json = serde_json::to_vec(cfg).map_err(|e| format!("serialize CircuitConfig: {e}"))?;

    let req_ptr = wg_alloc
        .call(&mut store, req_json.len() as u32)
        .map_err(|e| format!("wg_alloc(req): {e}"))?;
    let cfg_ptr = wg_alloc
        .call(&mut store, cfg_json.len() as u32)
        .map_err(|e| format!("wg_alloc(cfg): {e}"))?;

    memory
        .write(&mut store, req_ptr as usize, &req_json)
        .map_err(|e| format!("memory.write(req): {e}"))?;
    memory
        .write(&mut store, cfg_ptr as usize, &cfg_json)
        .map_err(|e| format!("memory.write(cfg): {e}"))?;

    let call_start = Instant::now();
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
        .map_err(|e| format!("synthesize_witness call: {e}"))?;
    let call_ms = elapsed_ms(call_start);

    let _ = wg_dealloc.call(&mut store, (req_ptr, req_json.len() as u32));
    let _ = wg_dealloc.call(&mut store, (cfg_ptr, cfg_json.len() as u32));

    if n < 0 {
        let err_ptr = err_ptr_fn
            .call(&mut store, ())
            .map_err(|e| format!("wg_last_error_ptr: {e}"))?;
        let err_len = err_len_fn
            .call(&mut store, ())
            .map_err(|e| format!("wg_last_error_len: {e}"))?;
        let mut buf = vec![0u8; err_len as usize];
        memory
            .read(&store, err_ptr as usize, &mut buf)
            .map_err(|e| format!("memory.read(err): {e}"))?;
        return Err(format!(
            "wasm synthesize_witness reported: {}",
            String::from_utf8_lossy(&buf)
        ));
    }

    let out_ptr = out_ptr_fn
        .call(&mut store, ())
        .map_err(|e| format!("wg_last_output_ptr: {e}"))?;
    let mut out = vec![0u8; n as usize];
    memory
        .read(&store, out_ptr as usize, &mut out)
        .map_err(|e| format!("memory.read(out): {e}"))?;

    let deserialize_start = Instant::now();
    let bundles = Vec::<WitnessBundle>::deserialize_uncompressed(&mut &out[..])
        .map_err(|e| format!("WitnessBundle CanonicalDeserialize: {e}"))?;
    let deserialize_ms = elapsed_ms(deserialize_start);

    Ok(WasmSynthesizeOutput {
        bundles,
        timing: WasmSynthesizeTiming {
            instantiate_ms,
            call_ms,
            deserialize_ms,
        },
    })
}
