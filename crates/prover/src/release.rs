//! Release loader — converts zkap-circuit's flat prefixed release bundle
//! (`<shape>-pk.bin`, `<shape>-manifest.json`, …) into a SHA-verified
//! unprefixed staged directory under `std::env::temp_dir()` that
//! `ArtifactSet::load_unsigned` can consume directly via `manifest_dir`.
//!
//! ## Layout
//!
//! Source (per `release_dir`, written by zkap-circuit):
//!
//! ```text
//! <release_dir>/
//!   1-of-1-manifest.json
//!   1-of-1-circuit.ar1cs
//!   1-of-1-pk.bin
//!   1-of-1-vk.bin
//!   1-of-1-pvk.bin
//!   1-of-1-Groth16Verifier.sol
//!   1-of-1-config.json
//!   1-of-1-SHA256SUMS          # entries: 7 unprefixed names
//!   3-of-3-* (same set)
//!   witness_gen.wasm           # shared across shapes
//!   SHA256SUMS                 # top-level (prefixed names + witness_gen.wasm)
//!   generate_hash, generate_setup       # CLI binaries — NOT staged
//! ```
//!
//! Staged (under `os.tmpdir()`):
//!
//! ```text
//! <tmp>/zkap-release-<release_sha>-<shape>/
//!   manifest.json
//!   circuit.ar1cs
//!   pk.bin
//!   vk.bin
//!   pvk.bin
//!   Groth16Verifier.sol
//!   config.json
//!   witness_gen.wasm
//! ```
//!
//! ## Cache key
//!
//! `release_sha` is the first 16 hex of SHA256 of the **per-shape**
//! `<shape>-SHA256SUMS` (NOT the top-level `SHA256SUMS`). Choosing
//! per-shape ensures re-baking 1-of-1 never busts the 3-of-3 cache and
//! vice versa.
//!
//! ## Concurrency
//!
//! `fs2::FileExt::lock_exclusive` on a sibling `<staged_dir>.lock` file
//! serialises concurrent jest workers / processes. The cold-path stages
//! into `<staged_dir>.tmp` and atomic-renames into place after full SHA
//! validation. A SIGKILL'd worker holding the lock releases it via OS
//! advisory-lock semantics — hand-rolled `O_EXCL` would leak the lock.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::error::ReleaseError;

/// Successful result of [`load_release`].
#[derive(Debug, Clone)]
pub struct LoadedRelease {
    /// Absolute path to the unprefixed staged bundle directory. Suitable
    /// for `ArtifactSet::load_unsigned(&manifest, staged_dir)`.
    pub staged_dir: PathBuf,
    /// First 16 hex chars of SHA256 of the per-shape `<shape>-SHA256SUMS`
    /// file. Used as the cache-key segment so re-baking one shape does
    /// not bust the other's cache.
    pub release_sha: String,
    /// Echo of the input `shape` post-validation (`"1-of-1"` / `"3-of-3"`).
    pub shape: String,
    /// Raw JSON text of the per-shape `manifest.json` — already
    /// SHA-verified by this loader. Callers can `serde_json::from_str`
    /// it to read `manifest_version`, `circuit_id`, etc., without
    /// re-opening the file.
    pub manifest_json: String,
}

/// Shapes accepted by the loader. Anything else → [`ReleaseError::UnknownShape`].
const SUPPORTED_SHAPES: &[&str] = &["1-of-1", "3-of-3"];

/// Unprefixed artifact names listed in the per-shape `<shape>-SHA256SUMS`.
/// These are sourced from `<release_dir>/<shape>-<name>` and staged as
/// `<staged_dir>/<name>`.
const PER_SHAPE_ARTIFACTS: &[&str] = &[
    "manifest.json",
    "circuit.ar1cs",
    "pk.bin",
    "vk.bin",
    "pvk.bin",
    "Groth16Verifier.sol",
    "config.json",
];

/// The witness-gen wasm artifact lives at the release-dir root (shared
/// across shapes). It is **not** in `<shape>-SHA256SUMS`; its expected
/// SHA is read from `manifest.artifacts.witness_gen.sha256`.
const WITNESS_GEN_NAME: &str = "witness_gen.wasm";
const WITNESS_GEN_COMPAT_MESSAGE: &str = concat!(
    "witness_gen.wasm is required by zkap-zkp wasm witness proving; ",
    "use a zkap-circuit release that includes witness_gen.wasm and ",
    "manifest artifacts.witness_gen.sha256"
);

/// Load a zkap-circuit release bundle into a SHA-verified unprefixed
/// staged directory.
///
/// See the [module-level docs](self) for layout, cache-key, and
/// concurrency semantics.
///
/// `shape` must be one of [`"1-of-1"`, `"3-of-3"`]; anything else
/// returns [`ReleaseError::UnknownShape`] before any filesystem access.
pub fn load_release(release_dir: &Path, shape: &str) -> Result<LoadedRelease, ReleaseError> {
    if !SUPPORTED_SHAPES.contains(&shape) {
        return Err(ReleaseError::UnknownShape(shape.to_string()));
    }

    // ── Step 1: load the per-shape SHA256SUMS and derive the cache key. ──
    let sums_path = release_dir.join(format!("{shape}-SHA256SUMS"));
    let sums_text = fs::read_to_string(&sums_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ReleaseError::MissingArtifact(format!("{}", sums_path.display()))
        } else {
            ReleaseError::IoError(e)
        }
    })?;
    let expected_shas = parse_sha256sums(&sums_text)?;

    let release_sha = {
        let mut hasher = Sha256::new();
        hasher.update(sums_text.as_bytes());
        let digest = hasher.finalize();
        hex::encode(digest).chars().take(16).collect::<String>()
    };

    // ── Step 2: derive the cache paths. ──────────────────────────────────
    let cache_root = std::env::temp_dir();
    let staged_dir = cache_root.join(format!("zkap-release-{release_sha}-{shape}"));
    let lock_path = staged_dir.with_extension("lock");
    let tmp_dir = staged_dir.with_extension("tmp");

    // ── Step 3: acquire exclusive advisory lock. ─────────────────────────
    // fs2::FileExt::lock_exclusive is mandatory — hand-rolled O_EXCL
    // would leak the lock on SIGKILL'd workers.
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| ReleaseError::LockFailure(format!("open {}: {e}", lock_path.display())))?;
    lock_file
        .lock_exclusive()
        .map_err(|e| ReleaseError::LockFailure(format!("lock {}: {e}", lock_path.display())))?;

    // ── Step 4: idempotent fast path or cold stage. ──────────────────────
    let outcome = (|| -> Result<String, ReleaseError> {
        // Warm path: stage dir exists and contains manifest.json. Re-verify
        // every artifact against the per-shape sums + manifest. If any
        // SHA disagrees, fall through to cold staging — the cache is
        // corrupt or stale.
        if staged_dir.join("manifest.json").exists() {
            match verify_existing_stage(&staged_dir, &expected_shas) {
                Ok(manifest_json) => return Ok(manifest_json),
                Err(ReleaseError::IntegrityFailure { .. })
                | Err(ReleaseError::MissingArtifact(_))
                | Err(ReleaseError::MalformedManifest(_)) => {
                    // Stale / corrupt cache — wipe and re-stage.
                    let _ = fs::remove_dir_all(&staged_dir);
                }
                Err(other) => return Err(other),
            }
        }

        stage_cold(release_dir, shape, &tmp_dir, &staged_dir, &expected_shas)
    })();

    // Release the advisory lock regardless of outcome.
    let _ = FileExt::unlock(&lock_file);

    let manifest_json = outcome?;

    Ok(LoadedRelease {
        staged_dir,
        release_sha,
        shape: shape.to_string(),
        manifest_json,
    })
}

/// Parse a `sha256sum`-style file (`<hex>  <name>\n` per line). Lines that
/// are empty or start with `#` are ignored.
fn parse_sha256sums(text: &str) -> Result<HashMap<String, String>, ReleaseError> {
    let mut map = HashMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // sha256sum output: 64-hex, two spaces, filename. We accept any
        // run of whitespace ≥ 1 to be tolerant of single-space variants.
        let mut parts = line.splitn(2, char::is_whitespace);
        let sha = parts.next().ok_or_else(|| {
            ReleaseError::MalformedManifest(format!("SHA256SUMS line {}: empty", idx + 1))
        })?;
        let rest = parts
            .next()
            .ok_or_else(|| {
                ReleaseError::MalformedManifest(format!(
                    "SHA256SUMS line {}: missing filename ({line:?})",
                    idx + 1
                ))
            })?
            .trim_start();
        // Some sha256sum outputs prefix the filename with `*` (binary mode).
        let name = rest.strip_prefix('*').unwrap_or(rest);
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ReleaseError::MalformedManifest(format!(
                "SHA256SUMS line {}: invalid hex digest ({sha:?})",
                idx + 1
            )));
        }
        map.insert(name.to_string(), sha.to_ascii_lowercase());
    }
    Ok(map)
}

/// Stream-SHA256 a file in 1 MiB chunks. Sub-second for 700 MB on a
/// modern SSD.
fn sha256_file(path: &Path) -> Result<String, ReleaseError> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ReleaseError::MissingArtifact(format!("{}", path.display()))
        } else {
            ReleaseError::IoError(e)
        }
    })?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Streaming-copy `src` → `dst` while hashing the bytes once. Returns the
/// hex SHA256 of the copied content so the caller can verify without a
/// second pass over the file.
fn copy_and_hash(src: &Path, dst: &Path) -> Result<String, ReleaseError> {
    let in_file = File::open(src).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ReleaseError::MissingArtifact(format!("{}", src.display()))
        } else {
            ReleaseError::IoError(e)
        }
    })?;
    let mut reader = BufReader::with_capacity(1024 * 1024, in_file);
    let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, File::create(dst)?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut writer, &buf[..n])?;
    }
    std::io::Write::flush(&mut writer)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Verify an existing staged dir against the per-shape sums + manifest.
/// Returns the manifest JSON text on success.
fn verify_existing_stage(
    staged_dir: &Path,
    expected_shas: &HashMap<String, String>,
) -> Result<String, ReleaseError> {
    // First confirm every per-shape artifact is present + SHA-matches.
    for name in PER_SHAPE_ARTIFACTS {
        let path = staged_dir.join(name);
        if !path.exists() {
            return Err(ReleaseError::MissingArtifact(format!(
                "{} (warm-cache check)",
                path.display()
            )));
        }
        let actual = sha256_file(&path)?;
        let expected = expected_shas.get(*name).ok_or_else(|| {
            ReleaseError::MalformedManifest(format!(
                "per-shape SHA256SUMS missing entry for {name}"
            ))
        })?;
        if &actual != expected {
            return Err(ReleaseError::IntegrityFailure {
                artifact: (*name).to_string(),
                expected: expected.clone(),
                actual,
            });
        }
    }

    // Then parse the staged manifest and verify witness_gen.wasm against
    // it (witness_gen is not in <shape>-SHA256SUMS).
    let manifest_text = fs::read_to_string(staged_dir.join("manifest.json"))?;
    let witness_expected = extract_witness_gen_sha(&manifest_text)?;
    let witness_path = staged_dir.join(WITNESS_GEN_NAME);
    if !witness_path.exists() {
        return Err(ReleaseError::MissingArtifact(format!(
            "{} (warm-cache check; {WITNESS_GEN_COMPAT_MESSAGE})",
            witness_path.display(),
        )));
    }
    let witness_actual = sha256_file(&witness_path)?;
    if witness_actual != witness_expected {
        return Err(ReleaseError::IntegrityFailure {
            artifact: WITNESS_GEN_NAME.to_string(),
            expected: witness_expected,
            actual: witness_actual,
        });
    }

    Ok(manifest_text)
}

/// Cold-stage `<shape>-<artifact>` → `<tmp_dir>/<artifact>` + atomic
/// rename `<tmp_dir>` → `<staged_dir>`. CLI binaries are intentionally
/// not copied. Returns the manifest JSON text on success.
fn stage_cold(
    release_dir: &Path,
    shape: &str,
    tmp_dir: &Path,
    staged_dir: &Path,
    expected_shas: &HashMap<String, String>,
) -> Result<String, ReleaseError> {
    // Wipe any half-staged leftovers from a prior crashed run.
    if tmp_dir.exists() {
        fs::remove_dir_all(tmp_dir)?;
    }
    fs::create_dir_all(tmp_dir)?;

    // Stage every per-shape artifact. We copy + hash in one pass.
    for name in PER_SHAPE_ARTIFACTS {
        let src = release_dir.join(format!("{shape}-{name}"));
        let dst = tmp_dir.join(name);
        let expected = expected_shas.get(*name).ok_or_else(|| {
            ReleaseError::MalformedManifest(format!(
                "per-shape SHA256SUMS missing entry for {name}"
            ))
        })?;
        let actual = copy_and_hash(&src, &dst).inspect_err(|_e| {
            // Best-effort cleanup of partially staged dir on failure.
            let _ = fs::remove_dir_all(tmp_dir);
        })?;
        if &actual != expected {
            let _ = fs::remove_dir_all(tmp_dir);
            return Err(ReleaseError::IntegrityFailure {
                artifact: (*name).to_string(),
                expected: expected.clone(),
                actual,
            });
        }
    }

    // Stage the shared witness_gen.wasm and verify against the manifest
    // we just staged (already SHA-verified above).
    let manifest_text = fs::read_to_string(tmp_dir.join("manifest.json"))?;
    let witness_expected = match extract_witness_gen_sha(&manifest_text) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir_all(tmp_dir);
            return Err(e);
        }
    };

    let witness_src = release_dir.join(WITNESS_GEN_NAME);
    let witness_dst = tmp_dir.join(WITNESS_GEN_NAME);
    if !witness_src.exists() {
        let _ = fs::remove_dir_all(tmp_dir);
        return Err(ReleaseError::MissingArtifact(format!(
            "{} ({WITNESS_GEN_COMPAT_MESSAGE})",
            witness_src.display(),
        )));
    }
    let witness_actual = copy_and_hash(&witness_src, &witness_dst).inspect_err(|_e| {
        let _ = fs::remove_dir_all(tmp_dir);
    })?;
    if witness_actual != witness_expected {
        let _ = fs::remove_dir_all(tmp_dir);
        return Err(ReleaseError::IntegrityFailure {
            artifact: WITNESS_GEN_NAME.to_string(),
            expected: witness_expected,
            actual: witness_actual,
        });
    }

    // The lock serializes all writers for this cache key, so any existing
    // final directory here is stale or incomplete. Replace it with the
    // fully verified tmp dir.
    if staged_dir.exists() {
        fs::remove_dir_all(staged_dir)?;
    }
    fs::rename(tmp_dir, staged_dir).map_err(|e| {
        let _ = fs::remove_dir_all(tmp_dir);
        ReleaseError::IoError(e)
    })?;

    Ok(manifest_text)
}

/// Pull `artifacts.witness_gen.sha256` out of the per-shape manifest.
/// Returns [`ReleaseError::MalformedManifest`] if the JSON is invalid or
/// the field is missing.
fn extract_witness_gen_sha(manifest_text: &str) -> Result<String, ReleaseError> {
    let v: serde_json::Value = serde_json::from_str(manifest_text)
        .map_err(|e| ReleaseError::MalformedManifest(format!("manifest.json: {e}")))?;
    let sha = v
        .get("artifacts")
        .and_then(|a| a.get("witness_gen"))
        .and_then(|w| w.get("sha256"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            ReleaseError::MalformedManifest(
                format!(
                    "manifest.json: artifacts.witness_gen.sha256 missing or not a string ({WITNESS_GEN_COMPAT_MESSAGE})"
                ),
            )
        })?;
    Ok(sha.to_ascii_lowercase())
}
