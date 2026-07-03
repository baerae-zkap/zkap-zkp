//! Release loader — converts zkap-circuit's flat prefixed release bundle
//! (`<shape>-pk.bin`, `<shape>-manifest.json`, …) into a SHA-verified
//! unprefixed staged directory under `std::env::temp_dir()` that
//! `ArtifactSet::load_unsigned` can consume directly via `manifest_dir`.
//!
//! The loader is **CRS-only**: it stages the 7 per-shape CRS artifacts and
//! nothing else. `witness_gen.wasm` is distributed independently of the CRS
//! (see [`load_witness_gen`]); it is no longer part of this bundle.
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
//!   SHA256SUMS                 # top-level (prefixed names)
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
use zkap_service::WitnessGenSidecar;

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
    /// The CRS shape identity (`ar1cs_blake3`) parsed from the staged
    /// `manifest.json`. Pass this to [`load_witness_gen`] as
    /// `crs_ar1cs_blake3` to gate an independently-distributed
    /// `witness_gen.wasm` against the loaded CRS shape.
    pub ar1cs_blake3: String,
}

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

/// Load a zkap-circuit release bundle into a SHA-verified unprefixed
/// staged directory.
///
/// See the [module-level docs](self) for layout, cache-key, and
/// concurrency semantics.
///
/// The loader is **k-of-n-agnostic**: `shape` is a bundle selector, not a
/// gated enum — any `<shape>-manifest.json` / `<shape>-SHA256SUMS` present in
/// `release_dir` loads (n/k/limits come from the bundle's config.json). The
/// only constraint is a `[A-Za-z0-9._-]` charset check that keeps `shape` from
/// injecting path separators into the `<shape>-<artifact>` file names; an
/// unknown-but-well-formed shape simply fails later as a missing artifact.
pub fn load_release(release_dir: &Path, shape: &str) -> Result<LoadedRelease, ReleaseError> {
    if shape.is_empty() || !shape.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
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
    // SUMS rows may be keyed by the unprefixed staging name or the
    // `<shape>-<name>` form; strip the `<shape>-` prefix so both match the
    // staging names verified below.
    let shape_prefix = format!("{shape}-");
    let expected_shas: HashMap<String, String> = expected_shas
        .into_iter()
        .map(|(name, sha)| {
            let name = name
                .strip_prefix(&shape_prefix)
                .map(str::to_string)
                .unwrap_or(name);
            (name, sha)
        })
        .collect();

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
    let ar1cs_blake3 = extract_ar1cs_blake3(&manifest_json)?;

    Ok(LoadedRelease {
        staged_dir,
        release_sha,
        shape: shape.to_string(),
        manifest_json,
        ar1cs_blake3,
    })
}

/// Pull the CRS shape identity (`ar1cs_blake3`) out of the per-shape
/// manifest. Returns [`ReleaseError::MalformedManifest`] if the JSON is
/// invalid or the field is missing / not a string.
fn extract_ar1cs_blake3(manifest_text: &str) -> Result<String, ReleaseError> {
    let v: serde_json::Value = serde_json::from_str(manifest_text)
        .map_err(|e| ReleaseError::MalformedManifest(format!("manifest.json: {e}")))?;
    let blake3 = v
        .get("ar1cs_blake3")
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            ReleaseError::MalformedManifest(
                "manifest.json: ar1cs_blake3 missing or not a string".to_string(),
            )
        })?;
    Ok(blake3.to_string())
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

    // Return the staged manifest text. The loader is CRS-only;
    // witness_gen.wasm is distributed independently (see load_witness_gen).
    let manifest_text = fs::read_to_string(staged_dir.join("manifest.json"))?;
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

    // Read back the staged manifest text (already SHA-verified above). The
    // loader is CRS-only; witness_gen.wasm is distributed independently
    // (see load_witness_gen).
    let manifest_text = fs::read_to_string(tmp_dir.join("manifest.json"))?;

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

/// Load and verify an independently-distributed `witness_gen.wasm` against
/// its sidecar. `wasm_path`/`sidecar_path` come from the app (fetched from
/// the witness-gen release channel), decoupled from the CRS `manifest_dir`.
/// `crs_ar1cs_blake3` is the loaded CRS's `ar1cs_blake3` (see
/// [`LoadedRelease::ar1cs_blake3`]). Verifies sidecar sha256(wasm) and that
/// the CRS shape is in `compatible_ar1cs_blake3`; returns the wasm bytes.
pub fn load_witness_gen(
    wasm_path: &Path,
    sidecar_path: &Path,
    crs_ar1cs_blake3: &str,
) -> Result<Vec<u8>, ReleaseError> {
    let sidecar_bytes = fs::read(sidecar_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ReleaseError::MissingArtifact(format!("{}", sidecar_path.display()))
        } else {
            ReleaseError::IoError(e)
        }
    })?;
    let sidecar = WitnessGenSidecar::from_json(&sidecar_bytes)?;

    let wasm_bytes = fs::read(wasm_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ReleaseError::MissingArtifact(format!("{}", wasm_path.display()))
        } else {
            ReleaseError::IoError(e)
        }
    })?;

    sidecar.verify_wasm_sha(&wasm_bytes)?;
    sidecar.require_compatible(crs_ar1cs_blake3)?;

    Ok(wasm_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A real CRS `ar1cs_blake3` shape (64 lowercase-hex). Listed in the
    /// sidecar's `compatible_ar1cs_blake3` for the happy-path tests.
    const BLAKE3_KNOWN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    /// A different valid 64-lc-hex shape, deliberately NOT listed.
    const BLAKE3_OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    /// Unique scratch dir under the OS tmpdir — no `tempfile` dep in this
    /// crate, matching the loader's own reliance on `std::env::temp_dir()`.
    fn scratch_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "zkap-prover-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Write a `witness_gen.wasm` + `witness_gen.json` sidecar into `dir`,
    /// returning (wasm_path, sidecar_path). `sha` / `compatible` are written
    /// verbatim so callers can inject a wrong sha or an incompatible list.
    fn write_fixture(
        dir: &Path,
        wasm: &[u8],
        sha: &str,
        compatible: &[&str],
    ) -> (PathBuf, PathBuf) {
        let wasm_path = dir.join("witness_gen.wasm");
        fs::write(&wasm_path, wasm).unwrap();
        let sidecar_path = dir.join("witness_gen.json");
        let compat = compatible
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            "{{\"version\":\"v0.0.0-test\",\"sha256\":\"{sha}\",\"compatible_ar1cs_blake3\":[{compat}]}}"
        );
        fs::write(&sidecar_path, json).unwrap();
        (wasm_path, sidecar_path)
    }

    /// Write a minimal synthetic release: tiny `<shape>-<name>` artifacts
    /// plus a per-shape SUMS whose rows are unprefixed staging names when
    /// `prefixed_rows` is false, or `<shape>-<name>` when true.
    fn write_release_fixture(dir: &Path, shape: &str, prefixed_rows: bool) {
        let manifest = format!("{{\"ar1cs_blake3\":\"{BLAKE3_KNOWN}\"}}");
        let artifacts: Vec<(&str, Vec<u8>)> = vec![
            ("circuit.ar1cs", b"ar1cs".to_vec()),
            ("pk.bin", b"pk".to_vec()),
            ("vk.bin", b"vk".to_vec()),
            ("pvk.bin", b"pvk".to_vec()),
            ("Groth16Verifier.sol", b"sol".to_vec()),
            ("config.json", b"{}".to_vec()),
            ("manifest.json", manifest.into_bytes()),
        ];
        let mut sums = String::new();
        for (name, bytes) in &artifacts {
            fs::write(dir.join(format!("{shape}-{name}")), bytes).unwrap();
            let row = if prefixed_rows {
                format!("{shape}-{name}")
            } else {
                (*name).to_string()
            };
            sums.push_str(&format!("{}  {}\n", sha256_hex(bytes), row));
        }
        fs::write(dir.join(format!("{shape}-SHA256SUMS")), sums).unwrap();
    }

    #[test]
    fn load_release_is_k_of_n_agnostic_arbitrary_shape_passes_gate() {
        // A never-before-seen shape must NOT be rejected at a gate — it flows
        // to file access and fails only as a missing artifact. k-of-n is a
        // bundle selector, not an allowlist.
        let dir = scratch_dir();
        let err = load_release(&dir, "5-of-9").unwrap_err();
        assert!(
            matches!(err, ReleaseError::MissingArtifact(_)),
            "arbitrary shape must reach FS, got {err:?}"
        );
    }

    #[test]
    fn load_release_rejects_shape_with_path_chars() {
        let dir = scratch_dir();
        for bad in ["../evil", "a/b", ""] {
            assert!(
                matches!(load_release(&dir, bad), Err(ReleaseError::UnknownShape(_))),
                "shape {bad:?} must be rejected by the charset guard"
            );
        }
    }

    #[test]
    fn load_release_accepts_prefixed_sums_rows() {
        // Rows keyed by the `<shape>-<name>` form must still verify.
        let dir = scratch_dir();
        write_release_fixture(&dir, "3-of-6", true);
        let loaded = load_release(&dir, "3-of-6").unwrap();
        assert_eq!(loaded.ar1cs_blake3, BLAKE3_KNOWN);
    }

    #[test]
    fn load_release_accepts_unprefixed_sums_rows() {
        let dir = scratch_dir();
        write_release_fixture(&dir, "3-of-3", false);
        let loaded = load_release(&dir, "3-of-3").unwrap();
        assert_eq!(loaded.ar1cs_blake3, BLAKE3_KNOWN);
    }

    #[test]
    fn load_witness_gen_ok_when_sha_and_shape_match() {
        let dir = scratch_dir();
        let wasm = b"synthetic witness_gen bytes \x00\x01\x02".as_slice();
        let sha = sha256_hex(wasm);
        let (wasm_path, sidecar_path) = write_fixture(&dir, wasm, &sha, &[BLAKE3_KNOWN]);

        let bytes = load_witness_gen(&wasm_path, &sidecar_path, BLAKE3_KNOWN)
            .expect("matching sha + compatible shape must load");
        assert_eq!(bytes, wasm);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_witness_gen_rejects_wrong_sha() {
        let dir = scratch_dir();
        let wasm = b"synthetic witness_gen bytes".as_slice();
        // Valid 64-lc-hex but NOT the sha of `wasm` → ShaMismatch.
        let wrong_sha = "0".repeat(64);
        let (wasm_path, sidecar_path) = write_fixture(&dir, wasm, &wrong_sha, &[BLAKE3_KNOWN]);

        let err = load_witness_gen(&wasm_path, &sidecar_path, BLAKE3_KNOWN)
            .expect_err("wrong sha in sidecar must error");
        assert!(matches!(err, ReleaseError::Sidecar(_)), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_witness_gen_rejects_incompatible_shape() {
        let dir = scratch_dir();
        let wasm = b"synthetic witness_gen bytes".as_slice();
        let sha = sha256_hex(wasm);
        // Sidecar lists only BLAKE3_OTHER; the CRS shape is BLAKE3_KNOWN.
        let (wasm_path, sidecar_path) = write_fixture(&dir, wasm, &sha, &[BLAKE3_OTHER]);

        let err = load_witness_gen(&wasm_path, &sidecar_path, BLAKE3_KNOWN)
            .expect_err("CRS shape not in compatible list must error");
        assert!(matches!(err, ReleaseError::Sidecar(_)), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_witness_gen_rejects_malformed_sidecar_json() {
        let dir = scratch_dir();
        let wasm = b"synthetic witness_gen bytes".as_slice();
        let wasm_path = dir.join("witness_gen.wasm");
        fs::write(&wasm_path, wasm).unwrap();
        let sidecar_path = dir.join("witness_gen.json");
        fs::write(&sidecar_path, b"{ this is not valid json").unwrap();

        let err = load_witness_gen(&wasm_path, &sidecar_path, BLAKE3_KNOWN)
            .expect_err("malformed sidecar JSON must error");
        assert!(matches!(err, ReleaseError::Sidecar(_)), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }
}
