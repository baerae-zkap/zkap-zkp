/**
 * artifact-manager.ts
 *
 * On-demand download, SHA256 verification, and local cache management
 * for zkap proving keys (PK). Node.js only. No external npm dependencies.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ArtifactEntry {
  url: string;
  sha256: string;
  size_bytes: number;
  compressed_size_bytes?: number;
}

export interface ArtifactManifest {
  version: string;
  circuit: string;
  artifacts: {
    proving_key: ArtifactEntry;
    verifying_key?: ArtifactEntry;
  };
  min_sdk_version: string;
  max_sdk_version: string;
}

export interface ArtifactManagerOptions {
  /** Override the local cache directory. Defaults to $XDG_CACHE_HOME/zkap or ~/.cache/zkap */
  cacheDir?: string;
  /** URL of the manifest JSON to fetch */
  manifestUrl: string;
  /** Progress callback: invoked with bytes downloaded so far and total bytes */
  onProgress?: (downloaded: number, total: number) => void;
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

const SDK_VERSION = "0.1.0";
const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 500;

// ---------------------------------------------------------------------------
// Cache path helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the default cache root: $XDG_CACHE_HOME/zkap → ~/.cache/zkap
 */
function defaultCacheDir(): string {
  const xdg = process.env["XDG_CACHE_HOME"];
  const base = xdg ? xdg : path.join(os.homedir(), ".cache");
  return path.join(base, "zkap");
}

/**
 * Return the expected cached file path for a circuit's proving key.
 *
 * @param cacheDir - Cache root directory (defaults to platform default)
 * @param circuit  - Circuit identifier, e.g. "zkap-v1"
 */
export function getCachedPkPath(
  cacheDir?: string,
  circuit?: string,
): string | null {
  const dir = cacheDir ?? defaultCacheDir();
  const circ = circuit ?? "zkap-v1";
  const candidate = path.join(dir, `${circ}-pk.bin`);
  try {
    fsSync.accessSync(candidate, fsSync.constants.R_OK);
    return candidate;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Version compatibility check
// ---------------------------------------------------------------------------

/**
 * Parse a semver string into [major, minor, patch] integers.
 * Returns null if the string is not parseable.
 */
function parseSemver(v: string): [number, number, number] | null {
  // Accept "1.x.x" wildcard notation: treat 'x' as 0 for comparison
  const normalized = v.replace(/x/gi, "0");
  const parts = normalized.split(".").map(Number);
  if (parts.length < 3 || parts.some(isNaN)) return null;
  return [parts[0]!, parts[1]!, parts[2]!];
}

/**
 * Compare two semver tuples. Returns:
 *   -1 if a < b, 0 if equal, 1 if a > b
 */
function compareSemver(
  a: [number, number, number],
  b: [number, number, number],
): -1 | 0 | 1 {
  for (let i = 0; i < 3; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return 0;
}

/**
 * Validate that SDK_VERSION is within [min_sdk_version, max_sdk_version].
 * Throws a descriptive error on mismatch.
 */
function checkVersionCompatibility(manifest: ArtifactManifest): void {
  const sdkParsed = parseSemver(SDK_VERSION);
  const minParsed = parseSemver(manifest.min_sdk_version);
  const maxParsed = parseSemver(manifest.max_sdk_version);

  if (!sdkParsed) {
    // Cannot parse SDK version — skip check rather than block
    return;
  }

  if (minParsed && compareSemver(sdkParsed, minParsed) < 0) {
    throw new Error(
      `[zkap/artifact-manager] SDK version ${SDK_VERSION} is below the minimum ` +
        `required version ${manifest.min_sdk_version} for circuit "${manifest.circuit}". ` +
        `Please upgrade the SDK.`,
    );
  }

  if (maxParsed && compareSemver(sdkParsed, maxParsed) > 0) {
    throw new Error(
      `[zkap/artifact-manager] SDK version ${SDK_VERSION} exceeds the maximum ` +
        `compatible version ${manifest.max_sdk_version} for circuit "${manifest.circuit}". ` +
        `Please use an older SDK version or update your artifact manifest.`,
    );
  }
}

// ---------------------------------------------------------------------------
// HTTP fetch helpers with retry + exponential backoff
// ---------------------------------------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch a URL with up to MAX_RETRIES attempts, exponential backoff.
 * Throws on non-2xx after all retries exhausted.
 */
async function fetchWithRetry(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await sleep(BASE_BACKOFF_MS * Math.pow(2, attempt - 1));
    }
    try {
      const res = await fetch(url, init);
      if (res.ok) return res;
      // Server errors (5xx) are retryable; client errors (4xx) are not
      if (res.status >= 400 && res.status < 500) {
        throw new Error(
          `[zkap/artifact-manager] HTTP ${res.status} fetching ${url}`,
        );
      }
      lastError = new Error(
        `[zkap/artifact-manager] HTTP ${res.status} fetching ${url}`,
      );
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

// ---------------------------------------------------------------------------
// SHA256 verification
// ---------------------------------------------------------------------------

/**
 * Compute the SHA256 hex digest of a file on disk.
 */
async function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fsSync.createReadStream(filePath);
    stream.on("data", (chunk: string | Buffer) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Streaming download with SHA256 rolling hash, Range resume, and progress
// ---------------------------------------------------------------------------

/**
 * Download a URL to a local file path, verifying SHA256 on-the-fly.
 * Supports HTTP Range header for resume if a partial file already exists.
 *
 * @param url        - Remote URL to download
 * @param destPath   - Final destination file path
 * @param expected   - Expected SHA256 hex digest
 * @param totalBytes - Expected total size in bytes (for progress reporting)
 * @param onProgress - Optional progress callback
 */
async function downloadVerified(
  url: string,
  destPath: string,
  expected: string,
  totalBytes: number,
  onProgress?: (downloaded: number, total: number) => void,
): Promise<void> {
  const tmpPath = `${destPath}.tmp`;

  // Check if there is a partial download to resume
  let resumeOffset = 0;
  try {
    const stat = await fs.stat(tmpPath);
    resumeOffset = stat.size;
  } catch {
    resumeOffset = 0;
  }

  let lastError: unknown;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await sleep(BASE_BACKOFF_MS * Math.pow(2, attempt - 1));
      // Re-check partial file size before each retry
      try {
        const stat = await fs.stat(tmpPath);
        resumeOffset = stat.size;
      } catch {
        resumeOffset = 0;
      }
    }

    try {
      const headers: Record<string, string> = {};
      if (resumeOffset > 0) {
        headers["Range"] = `bytes=${resumeOffset}-`;
      }

      const res = await fetch(url, { headers });

      if (!res.ok && res.status !== 206) {
        throw new Error(
          `[zkap/artifact-manager] HTTP ${res.status} downloading artifact from ${url}`,
        );
      }

      // Determine whether the server honored Range
      const isPartial = res.status === 206;
      if (!isPartial && resumeOffset > 0) {
        // Server did not support Range — restart from beginning
        resumeOffset = 0;
        await fs.unlink(tmpPath).catch(() => undefined);
      }

      const hash = crypto.createHash("sha256");

      // If resuming, we need to hash the already-downloaded portion first
      if (resumeOffset > 0) {
        await new Promise<void>((resolve, reject) => {
          const existingStream = fsSync.createReadStream(tmpPath);
          existingStream.on("data", (chunk: string | Buffer) => hash.update(chunk));
          existingStream.on("end", resolve);
          existingStream.on("error", reject);
        });
      }

      const body = res.body;
      if (!body) {
        throw new Error(
          "[zkap/artifact-manager] Response body is null — cannot download artifact",
        );
      }

      // Open the tmp file for appending (or writing fresh)
      const fileHandle = await fs.open(
        tmpPath,
        resumeOffset > 0 ? "a" : "w",
      );

      let downloaded = resumeOffset;

      try {
        const reader = body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            hash.update(value);
            await fileHandle.write(value);
            downloaded += value.byteLength;
            onProgress?.(downloaded, totalBytes);
          }
        }
      } finally {
        await fileHandle.close();
      }

      // Verify SHA256
      const digest = hash.digest("hex");
      if (digest !== expected) {
        // Delete corrupted partial/complete tmp file and retry
        await fs.unlink(tmpPath).catch(() => undefined);
        resumeOffset = 0;
        throw new Error(
          `[zkap/artifact-manager] SHA256 mismatch for artifact from ${url}. ` +
            `Expected: ${expected}, got: ${digest}. File deleted, will retry.`,
        );
      }

      // Atomic rename to final path
      await fs.rename(tmpPath, destPath);
      return;
    } catch (err) {
      lastError = err;
      // Check for disk space errors and surface them immediately
      if (isDiskSpaceError(err)) {
        const needed = formatBytes(totalBytes);
        throw new Error(
          `[zkap/artifact-manager] Insufficient disk space to download artifact. ` +
            `Required: ~${needed}. Free up space and try again.`,
        );
      }
    }
  }

  throw lastError;
}

// ---------------------------------------------------------------------------
// Disk space error detection
// ---------------------------------------------------------------------------

function isDiskSpaceError(err: unknown): boolean {
  if (err instanceof Error) {
    const msg = err.message.toUpperCase();
    // ENOSPC = POSIX no space left on device
    return msg.includes("ENOSPC") || msg.includes("NO SPACE LEFT");
  }
  return false;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${bytes} bytes`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Initialize artifacts: fetch the manifest, check SDK version compatibility,
 * verify or download the proving key, and return its local cache path.
 *
 * @param options - Configuration including manifestUrl and optional cacheDir/onProgress
 * @returns Absolute path to the cached proving key file
 */
export async function initArtifacts(
  options: ArtifactManagerOptions,
): Promise<string> {
  const { manifestUrl, onProgress } = options;
  const cacheDir = options.cacheDir ?? defaultCacheDir();

  // --- 1. Fetch and parse manifest (with retry) ---
  const manifestRes = await fetchWithRetry(manifestUrl);
  const manifest = (await manifestRes.json()) as ArtifactManifest;

  if (
    !manifest.circuit ||
    !manifest.artifacts?.proving_key?.url ||
    !manifest.artifacts?.proving_key?.sha256
  ) {
    throw new Error(
      `[zkap/artifact-manager] Manifest at ${manifestUrl} is missing required fields ` +
        `(circuit, artifacts.proving_key.url, artifacts.proving_key.sha256).`,
    );
  }

  // --- 2. SDK version compatibility check ---
  checkVersionCompatibility(manifest);

  // --- 3. Ensure cache directory exists ---
  await fs.mkdir(cacheDir, { recursive: true });

  const pk = manifest.artifacts.proving_key;
  const pkFileName = `${manifest.circuit}-pk.bin`;
  const pkPath = path.join(cacheDir, pkFileName);

  // --- 4. Check existing cache ---
  let cacheHit = false;
  try {
    await fs.access(pkPath, fsSync.constants.R_OK);
    // File exists — verify SHA256
    const digest = await sha256File(pkPath);
    if (digest === pk.sha256) {
      cacheHit = true;
    } else {
      // Stale or corrupted cache — remove and re-download
      await fs.unlink(pkPath);
    }
  } catch {
    // File does not exist — proceed to download
  }

  if (cacheHit) {
    return pkPath;
  }

  // --- 5. Download proving key with verification ---
  const totalBytes = pk.compressed_size_bytes ?? pk.size_bytes;
  await downloadVerified(pk.url, pkPath, pk.sha256, totalBytes, onProgress);

  return pkPath;
}
