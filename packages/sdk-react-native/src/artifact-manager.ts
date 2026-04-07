/**
 * artifact-manager — MVP implementation
 *
 * Included:  download, cache path management, SHA256 verification,
 *            atomic rename, max 3 retries, progress callback
 * Excluded:  HTTP Range resume, background download, advanced cache cleanup
 */

import * as FileSystem from 'expo-file-system';
import * as Crypto from 'expo-crypto';

// ──────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────

export interface ArtifactManifest {
  version: string;
  circuit: string;
  artifacts: {
    proving_key: {
      url: string;
      sha256: string;
      size_bytes: number;
      compressed_size_bytes?: number;
    };
  };
  min_sdk_version: string;
  max_sdk_version: string;
}

export interface InitProveArtifactsOptions {
  /** URL of the manifest.json that describes the proving key location */
  manifestUrl: string;
  /**
   * Local directory for caching the proving key.
   * Defaults to `<FileSystem.cacheDirectory>/zkap/`
   */
  cacheDir?: string;
  /**
   * Called periodically during download.
   * `downloaded` and `total` are in bytes.
   */
  onProgress?: (downloaded: number, total: number) => void;
}

// ──────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────

const MAX_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 1000;

// ──────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────

/**
 * Download (if not cached) and verify the Groth16 proving key.
 *
 * Returns the local file path to the cached proving key,
 * which should be passed to `prove()` as `request.pk_path`.
 *
 * @throws if download fails after 3 retries, or SHA256 verification fails
 */
export async function initProveArtifacts(
  options: InitProveArtifactsOptions
): Promise<string> {
  const cacheDir =
    options.cacheDir ??
    `${FileSystem.cacheDirectory}zkap/`;

  // Ensure cache directory exists
  await ensureDir(cacheDir);

  // 1. Download manifest
  const manifest = await fetchManifest(options.manifestUrl);

  // 2. Determine cache file path (version-namespaced to avoid stale cache)
  const pkInfo = manifest.artifacts.proving_key;
  const fileName = `zkap-${manifest.version}-pk.bin`;
  const pkCachePath = `${cacheDir}${fileName}`;
  const pkTmpPath = `${pkCachePath}.tmp`;

  // 3. Check if already cached and valid
  const fileInfo = await FileSystem.getInfoAsync(pkCachePath);
  if (fileInfo.exists) {
    const valid = await verifySha256(pkCachePath, pkInfo.sha256);
    if (valid) {
      return pkCachePath;
    }
    // Cache is corrupted — delete and re-download
    await FileSystem.deleteAsync(pkCachePath, { idempotent: true });
  }

  // 4. Download with retries
  await downloadWithRetry({
    url: pkInfo.url,
    tmpPath: pkTmpPath,
    totalBytes: pkInfo.size_bytes,
    onProgress: options.onProgress,
    maxRetries: MAX_RETRIES,
  });

  // 5. Verify SHA256
  const valid = await verifySha256(pkTmpPath, pkInfo.sha256);
  if (!valid) {
    await FileSystem.deleteAsync(pkTmpPath, { idempotent: true });
    throw new Error(
      '[zkap/artifact-manager] SHA256 verification failed. ' +
      'The downloaded file may be corrupted. Please try again.'
    );
  }

  // 6. Atomic rename: tmp → final cache path
  await FileSystem.moveAsync({ from: pkTmpPath, to: pkCachePath });

  return pkCachePath;
}

// ──────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────

async function ensureDir(dir: string): Promise<void> {
  const info = await FileSystem.getInfoAsync(dir);
  if (!info.exists) {
    await FileSystem.makeDirectoryAsync(dir, { intermediates: true });
  }
}

async function fetchManifest(url: string): Promise<ArtifactManifest> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `[zkap/artifact-manager] Failed to fetch manifest: HTTP ${response.status}`
    );
  }
  return response.json() as Promise<ArtifactManifest>;
}

interface DownloadOptions {
  url: string;
  tmpPath: string;
  totalBytes: number;
  onProgress?: (downloaded: number, total: number) => void;
  maxRetries: number;
}

async function downloadWithRetry(opts: DownloadOptions): Promise<void> {
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= opts.maxRetries; attempt++) {
    try {
      // Clean up any partial download from a previous attempt
      await FileSystem.deleteAsync(opts.tmpPath, { idempotent: true });

      const downloadResumable = FileSystem.createDownloadResumable(
        opts.url,
        opts.tmpPath,
        {},
        (progress) => {
          if (opts.onProgress) {
            opts.onProgress(
              progress.totalBytesWritten,
              progress.totalBytesExpectedToWrite > 0
                ? progress.totalBytesExpectedToWrite
                : opts.totalBytes
            );
          }
        }
      );

      const result = await downloadResumable.downloadAsync();
      if (!result || result.status !== 200) {
        throw new Error(
          `[zkap/artifact-manager] Download failed with status ${result?.status ?? 'unknown'}`
        );
      }

      return; // Success
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < opts.maxRetries) {
        const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
        await sleep(delay);
      }
    }
  }

  throw new Error(
    `[zkap/artifact-manager] Download failed after ${opts.maxRetries} attempts. ` +
    `Last error: ${lastError?.message ?? 'unknown'}`
  );
}

async function verifySha256(filePath: string, expectedHex: string): Promise<boolean> {
  try {
    // Read file as base64, then hash
    const base64 = await FileSystem.readAsStringAsync(filePath, {
      encoding: FileSystem.EncodingType.Base64,
    });
    const digest = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      base64,
      { encoding: Crypto.CryptoEncoding.BASE64 }
    );
    // Convert base64 digest to hex for comparison
    const digestHex = Buffer.from(digest, 'base64').toString('hex');
    return digestHex.toLowerCase() === expectedHex.toLowerCase();
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
