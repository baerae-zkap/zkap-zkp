import {
  deriveSelector as rnDeriveSelector,
  generateAnchor as rnGenerateAnchor,
  generateAudHash as rnGenerateAudHash,
  generateHash as rnGenerateHash,
  generateLeafHash as rnGenerateLeafHash,
  prove as rnProve,
} from '@baerae/zkap-zkp-react-native';
import { UnsupportedPlatformError } from './errors';
import { withFormattedMerklePaths } from './merkle';
import {
  RELEASE_ARTIFACT_NAMES,
  buildArtifactProgress,
  computeReleaseSha,
  findManifestArtifact,
  listManifestArtifacts,
  makeAbortError,
  normalizeCircuitConfig,
  normalizeSha256SumKeys,
  parseSha256Sums,
  releaseFileName,
  releaseFileUrl,
  sha256HexUtf8,
  sumManifestBytes,
  throwIfAborted,
  validateReleaseShape,
} from './release-shared';
import type {
  AnchorResult,
  AudHashResult,
  CachedReleaseInfo,
  CachedWitnessGenInfo,
  CircuitConfig,
  DownloadReleaseOpts,
  DownloadReleaseProgress,
  DownloadReleaseResult,
  DownloadWitnessGenOpts,
  DownloadWitnessGenProgress,
  DownloadWitnessGenResult,
  GetCachedReleaseInfoOpts,
  GetCachedWitnessGenInfoOpts,
  LoadReleaseOpts,
  LoadReleaseResult,
  PrepareProverResult,
  ProofOutput,
  ProofRequest,
  Secret,
  VerifyOutput,
  WitnessGenSidecar,
} from './types';

export * from './errors';
export * from './types';
export { normalizeCircuitConfig } from './release-shared';
export { formatMerklePathForCircuit } from './merkle';

type ReactNativeCircuitConfig = Parameters<typeof rnGenerateAnchor>[0];
type ReactNativeProofRequest = Parameters<typeof rnProve>[1];

function toReactNativeConfig(config: CircuitConfig): ReactNativeCircuitConfig {
  return {
    max_jwt_b64_len: config.maxJwtB64Len,
    max_payload_b64_len: config.maxPayloadB64Len,
    max_aud_len: config.maxAudLen,
    max_exp_len: config.maxExpLen,
    max_iss_len: config.maxIssLen,
    max_nonce_len: config.maxNonceLen,
    max_sub_len: config.maxSubLen,
    n: config.n,
    k: config.k,
    tree_height: config.treeHeight,
    num_audience_limit: config.numAudienceLimit,
    claims: config.claims,
    forbidden_string: config.forbiddenString,
  };
}

export async function initZkap(): Promise<void> {
  return undefined;
}

export async function generateHash(messages: string[]): Promise<string> {
  return rnGenerateHash(messages);
}

export async function generateAnchor(
  config: CircuitConfig,
  secrets: Secret[],
): Promise<AnchorResult> {
  return rnGenerateAnchor(toReactNativeConfig(config), secrets);
}

export async function deriveSelector(
  config: CircuitConfig,
  secrets: Secret[],
  anchorEvaluations: string[],
): Promise<number[]> {
  return rnDeriveSelector(
    toReactNativeConfig(config),
    secrets,
    anchorEvaluations,
  );
}

export async function generateAudHash(
  config: CircuitConfig,
  audList: string[],
): Promise<AudHashResult> {
  const result = await rnGenerateAudHash(toReactNativeConfig(config), audList);
  return {
    audHashes: result.aud_hashes,
    hAudList: result.h_aud_list,
  };
}

export async function generateLeafHash(
  config: CircuitConfig,
  iss: string,
  pkB64: string,
): Promise<string> {
  return rnGenerateLeafHash(toReactNativeConfig(config), iss, pkB64);
}

export async function prepareProver(
  _manifestDir: string,
  _witnessGenPath?: string,
  _witnessGenSidecarPath?: string,
): Promise<PrepareProverResult> {
  throw new UnsupportedPlatformError(
    'prepareProver',
    'react-native',
    '[zkap-zkp] prepareProver is only available in the Node.js runtime.',
  );
}

/**
 * Resolve the witness-generator paths for `prove()`.
 *
 * - Both omitted → co-located default (`<manifestDir>/witness_gen.wasm` +
 *   `<manifestDir>/witness_gen.json`); `manifestDir` is a plain path.
 * - Both provided → use them verbatim.
 * - Exactly one provided → throw, since a half-specified pair is always a bug.
 */
export function resolveWitnessGenPaths(
  manifestDir: string,
  witnessGenPath?: string,
  witnessGenSidecarPath?: string,
): { wasmPath: string; sidecarPath: string } {
  const hasWasm = witnessGenPath !== undefined;
  const hasSidecar = witnessGenSidecarPath !== undefined;
  if (hasWasm !== hasSidecar) {
    throw new Error(
      '[zkap-zkp] witnessGenPath and witnessGenSidecarPath must be provided together, or both omitted to use the co-located default.',
    );
  }
  if (hasWasm && hasSidecar) {
    return { wasmPath: witnessGenPath!, sidecarPath: witnessGenSidecarPath! };
  }
  const base = manifestDir.replace(/\/+$/, '');
  return {
    wasmPath: `${base}/witness_gen.wasm`,
    sidecarPath: `${base}/witness_gen.json`,
  };
}

export async function prove(
  config: CircuitConfig,
  request: ProofRequest,
): Promise<ProofOutput> {
  const { wasmPath, sidecarPath } = resolveWitnessGenPaths(
    request.manifestDir,
    request.witnessGenPath,
    request.witnessGenSidecarPath,
  );
  const result = await rnProve(
    toReactNativeConfig(config),
    withFormattedMerklePaths({
      ...request,
      witnessGenPath: wasmPath,
      witnessGenSidecarPath: sidecarPath,
    }) as unknown as ReactNativeProofRequest,
  );
  return {
    proofs: result.proofs,
    sharedInputs: result.shared_inputs,
    partialRhsList: result.partial_rhs_list,
    jwtExpList: result.jwt_exp_list,
  };
}

export async function loadRelease(
  _opts: LoadReleaseOpts,
): Promise<LoadReleaseResult> {
  throw new UnsupportedPlatformError(
    'loadRelease',
    'react-native',
    '[zkap-zkp] loadRelease is only available in the Node.js runtime.',
  );
}

interface ExpoFileInfo {
  exists: boolean;
  isDirectory?: boolean;
  size?: number;
}

interface ExpoDownloadProgressData {
  totalBytesWritten: number;
  /** Total bytes expected, or `-1` when the server did not send `Content-Length`. */
  totalBytesExpectedToWrite: number;
}

interface ExpoDownloadResumable {
  downloadAsync(): Promise<unknown>;
  pauseAsync(): Promise<unknown>;
  resumeAsync(): Promise<unknown>;
  cancelAsync(): Promise<void>;
}

interface ExpoFileSystem {
  cacheDirectory?: string | null;
  documentDirectory?: string | null;
  deleteAsync(uri: string, options?: { idempotent?: boolean }): Promise<void>;
  createDownloadResumable(
    uri: string,
    fileUri: string,
    options?: Record<string, unknown>,
    callback?: (data: ExpoDownloadProgressData) => void,
    resumeData?: string,
  ): ExpoDownloadResumable;
  getInfoAsync(fileUri: string): Promise<ExpoFileInfo>;
  makeDirectoryAsync(uri: string, options?: { intermediates?: boolean }): Promise<void>;
  moveAsync(options: { from: string; to: string }): Promise<void>;
  readAsStringAsync(fileUri: string): Promise<string>;
  writeAsStringAsync(fileUri: string, contents: string): Promise<void>;
}

async function loadExpoFileSystem(): Promise<ExpoFileSystem> {
  try {
    // Use a STRING LITERAL specifier: Metro (React Native) cannot bundle
    // `import()` with a variable argument — the module is omitted from the
    // bundle and the dynamic import fails at runtime. A literal lets Metro
    // statically include expo-file-system/legacy. (Node/vitest worked either way.)
    return (await import('expo-file-system/legacy')) as ExpoFileSystem;
  } catch (error) {
    const wrapped = new Error(
      '[zkap-zkp] downloadRelease/loadCircuitConfig in React Native require expo-file-system. Install it with `npx expo install expo-file-system`.',
    );
    (wrapped as Error & { cause?: unknown }).cause = error;
    throw wrapped;
  }
}

function getFetch(fetchImpl?: typeof fetch): typeof fetch {
  const resolved = fetchImpl ?? globalThis.fetch;
  if (typeof resolved !== 'function') {
    throw new Error('[zkap-zkp] downloadRelease requires fetch support.');
  }
  return resolved;
}

async function fetchText(
  url: string,
  fetchImpl: typeof fetch,
  signal?: AbortSignal,
): Promise<string> {
  const response = await fetchImpl(url, signal ? { signal } : undefined);
  if (!response.ok) {
    throw new Error(`[zkap-zkp] failed to fetch ${url}: HTTP ${response.status}`);
  }
  return response.text();
}

function ensureTrailingSlash(uri: string): string {
  return uri.endsWith('/') ? uri : `${uri}/`;
}

function toFileUri(pathOrUri: string): string {
  if (pathOrUri.startsWith('file://')) {
    return ensureTrailingSlash(pathOrUri);
  }
  return ensureTrailingSlash(`file://${pathOrUri}`);
}

function uriToPath(uri: string): string {
  return uri.replace(/^file:\/\//, '').replace(/\/$/, '');
}

async function fileSize(
  fs: ExpoFileSystem,
  fileUri: string,
): Promise<number | undefined> {
  const info = await fs.getInfoAsync(fileUri);
  if (!info.exists || info.isDirectory) return undefined;
  return typeof info.size === 'number' ? info.size : undefined;
}

async function readStagedManifest(
  fs: ExpoFileSystem,
  stagedDirUri: string,
): Promise<string | undefined> {
  try {
    return await fs.readAsStringAsync(`${stagedDirUri}manifest.json`);
  } catch {
    return undefined;
  }
}

/**
 * Validate a staged directory against its own manifest. React Native checks each
 * artifact's size (not content SHA256) — see {@link downloadRelease} for the rationale.
 * Fully offline: no SHA256SUMS needed.
 */
async function isStagedManifestValid(
  fs: ExpoFileSystem,
  stagedDirUri: string,
  manifestJson: string,
): Promise<boolean> {
  try {
    for (const artifact of listManifestArtifacts(manifestJson)) {
      const actualSize = await fileSize(fs, `${stagedDirUri}${artifact.path}`);
      if (actualSize === undefined) return false;
      if (artifact.size !== undefined && actualSize !== artifact.size) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

async function isCachedReleaseValid(
  fs: ExpoFileSystem,
  stagedDirUri: string,
  sha256Sums: Map<string, string>,
): Promise<boolean> {
  const manifestJson = await readStagedManifest(fs, stagedDirUri);
  if (manifestJson === undefined) return false;
  const expectedManifestSha = sha256Sums.get('manifest.json');
  if (
    !expectedManifestSha ||
    sha256HexUtf8(manifestJson) !== expectedManifestSha
  ) {
    return false;
  }
  return isStagedManifestValid(fs, stagedDirUri, manifestJson);
}

interface ReleaseProgressState {
  /** Bytes already accounted for by fully-completed artifacts. */
  releaseBaseBytes: number;
  /** Total downloaded bytes of the whole release, when known. */
  releaseTotalBytes: number | undefined;
}

async function downloadFile(
  fs: ExpoFileSystem,
  url: string,
  destinationUri: string,
  expectedBytes: number | undefined,
  progress: Pick<
    DownloadReleaseProgress,
    'phase' | 'artifact' | 'completedArtifacts' | 'totalArtifacts'
  >,
  releaseState: ReleaseProgressState,
  onProgress: ((progress: DownloadReleaseProgress) => void) | undefined,
  signal: AbortSignal | undefined,
): Promise<void> {
  throwIfAborted(signal);

  let lastLoaded = 0;
  const task = fs.createDownloadResumable(
    url,
    destinationUri,
    undefined,
    (data) => {
      lastLoaded = data.totalBytesWritten;
      const artifactTotal =
        data.totalBytesExpectedToWrite > 0
          ? data.totalBytesExpectedToWrite
          : expectedBytes;
      const releaseLoadedBytes =
        releaseState.releaseTotalBytes !== undefined
          ? releaseState.releaseBaseBytes + data.totalBytesWritten
          : undefined;
      onProgress?.(
        buildArtifactProgress(
          progress,
          data.totalBytesWritten,
          artifactTotal,
          releaseLoadedBytes,
          releaseState.releaseTotalBytes,
        ),
      );
    },
  );

  const onAbort = (): void => {
    void task.cancelAsync();
  };
  signal?.addEventListener('abort', onAbort);
  try {
    await task.downloadAsync();
  } finally {
    signal?.removeEventListener('abort', onAbort);
  }
  throwIfAborted(signal);

  const actualSize = await fileSize(fs, destinationUri);
  if (expectedBytes !== undefined && actualSize !== expectedBytes) {
    await fs.deleteAsync(destinationUri, { idempotent: true });
    throw new Error(
      `[zkap-zkp] downloaded artifact has invalid size for ${progress.artifact}: expected ${expectedBytes}, got ${actualSize ?? 'missing'}`,
    );
  }

  // Emit a final per-artifact event so the UI can settle this artifact at 100%.
  const artifactBytes = actualSize ?? lastLoaded;
  const advance = expectedBytes ?? artifactBytes;
  const releaseLoadedBytes =
    releaseState.releaseTotalBytes !== undefined
      ? releaseState.releaseBaseBytes + advance
      : undefined;
  onProgress?.(
    buildArtifactProgress(
      progress,
      artifactBytes,
      expectedBytes ?? artifactBytes,
      releaseLoadedBytes,
      releaseState.releaseTotalBytes,
    ),
  );
  releaseState.releaseBaseBytes += advance;
}

function assertReleaseSha(
  actual: string,
  expected: string | undefined,
): void {
  if (expected && expected.toLowerCase() !== actual) {
    throw new Error(
      `[zkap-zkp] release SHA mismatch: expected ${expected}, got ${actual}`,
    );
  }
}

export async function downloadRelease(
  opts: DownloadReleaseOpts,
): Promise<DownloadReleaseResult> {
  const fs = await loadExpoFileSystem();
  const fetchImpl = getFetch(opts.fetch);
  const signal = opts.signal;
  const shape = opts.shape;
  validateReleaseShape(shape);
  throwIfAborted(signal);
  const sha256SumsName = `${shape}-SHA256SUMS`;
  const sha256SumsUrl = releaseFileUrl(opts.baseUrl, sha256SumsName);

  opts.onProgress?.({ phase: 'metadata', artifact: sha256SumsName });
  const sha256SumsText = await fetchText(sha256SumsUrl, fetchImpl, signal);
  const releaseSha = computeReleaseSha(sha256SumsText);
  assertReleaseSha(releaseSha, opts.expectedReleaseSha);
  const sha256Sums = normalizeSha256SumKeys(parseSha256Sums(sha256SumsText), shape);

  const rootUri = toFileUri(
    opts.cacheDir ?? fs.cacheDirectory ?? fs.documentDirectory ?? '',
  );
  if (rootUri === 'file://') {
    throw new Error('[zkap-zkp] no React Native filesystem cache directory is available');
  }
  const stagedDirUri = `${rootUri}zkap-release-${releaseSha}-${shape}/`;
  const tmpStagedDirUri = `${rootUri}zkap-release-${releaseSha}-${shape}.tmp/`;

  if (!opts.force && (await isCachedReleaseValid(fs, stagedDirUri, sha256Sums))) {
    const manifestJson = await fs.readAsStringAsync(`${stagedDirUri}manifest.json`);
    return {
      stagedDir: uriToPath(stagedDirUri),
      manifestJson,
      shape,
      releaseSha,
    };
  }

  await fs.deleteAsync(tmpStagedDirUri, { idempotent: true });
  await fs.makeDirectoryAsync(tmpStagedDirUri, { intermediates: true });

  try {
    const expectedManifestSha = sha256Sums.get('manifest.json');
    if (!expectedManifestSha) {
      throw new Error(`[zkap-zkp] ${sha256SumsName} missing manifest.json`);
    }
    const manifestJson = await fetchText(
      releaseFileUrl(opts.baseUrl, releaseFileName(shape, 'manifest.json')),
      fetchImpl,
      signal,
    );
    const manifestSha = sha256HexUtf8(manifestJson);
    if (manifestSha !== expectedManifestSha) {
      throw new Error(
        `[zkap-zkp] manifest.json SHA256 mismatch: expected ${expectedManifestSha}, got ${manifestSha}`,
      );
    }
    await fs.writeAsStringAsync(`${tmpStagedDirUri}manifest.json`, manifestJson);

    const totalArtifacts = RELEASE_ARTIFACT_NAMES.length;
    // Whole-release total excludes manifest.json: it is fetched as text above and is tiny.
    const releaseState: ReleaseProgressState = {
      releaseBaseBytes: 0,
      releaseTotalBytes: sumManifestBytes(manifestJson, {
        excludePaths: ['manifest.json'],
      }),
    };
    let completedArtifacts = 1;
    opts.onProgress?.({
      phase: 'artifact',
      artifact: 'manifest.json',
      completedArtifacts: 0,
      totalArtifacts,
      releaseLoadedBytes: releaseState.releaseTotalBytes !== undefined ? 0 : undefined,
      releaseTotalBytes: releaseState.releaseTotalBytes,
      percent: releaseState.releaseTotalBytes !== undefined ? 0 : undefined,
    });

    for (const artifactName of RELEASE_ARTIFACT_NAMES.filter(
      (name) => name !== 'manifest.json',
    )) {
      const manifestArtifact = findManifestArtifact(manifestJson, artifactName);
      await downloadFile(
        fs,
        releaseFileUrl(opts.baseUrl, releaseFileName(shape, artifactName)),
        `${tmpStagedDirUri}${artifactName}`,
        manifestArtifact.size,
        {
          phase: 'artifact',
          artifact: artifactName,
          completedArtifacts,
          totalArtifacts,
        },
        releaseState,
        opts.onProgress,
        signal,
      );
      completedArtifacts += 1;
    }

    opts.onProgress?.({
      phase: 'stage',
      completedArtifacts: totalArtifacts,
      totalArtifacts,
      releaseLoadedBytes: releaseState.releaseTotalBytes,
      releaseTotalBytes: releaseState.releaseTotalBytes,
      percent: releaseState.releaseTotalBytes !== undefined ? 1 : undefined,
    });
    await fs.deleteAsync(stagedDirUri, { idempotent: true });
    await fs.moveAsync({ from: tmpStagedDirUri, to: stagedDirUri });
    opts.onProgress?.({
      phase: 'done',
      completedArtifacts: totalArtifacts,
      totalArtifacts,
      releaseLoadedBytes: releaseState.releaseTotalBytes,
      releaseTotalBytes: releaseState.releaseTotalBytes,
      percent: releaseState.releaseTotalBytes !== undefined ? 1 : undefined,
    });

    return { stagedDir: uriToPath(stagedDirUri), manifestJson, shape, releaseSha };
  } catch (error) {
    await fs.deleteAsync(tmpStagedDirUri, { idempotent: true });
    if (signal?.aborted) {
      throw makeAbortError();
    }
    throw error;
  }
}

export async function getCachedReleaseInfo(
  opts: GetCachedReleaseInfoOpts,
): Promise<CachedReleaseInfo> {
  validateReleaseShape(opts.shape);
  const fs = await loadExpoFileSystem();
  const releaseSha = opts.expectedReleaseSha.toLowerCase();
  const rootUri = toFileUri(
    opts.cacheDir ?? fs.cacheDirectory ?? fs.documentDirectory ?? '',
  );
  if (rootUri === 'file://') {
    throw new Error('[zkap-zkp] no React Native filesystem cache directory is available');
  }
  const stagedDirUri = `${rootUri}zkap-release-${releaseSha}-${opts.shape}/`;

  const manifestJson = await readStagedManifest(fs, stagedDirUri);
  if (manifestJson === undefined) {
    return { exists: false, valid: false, releaseSha };
  }

  let totalBytes: number | undefined;
  try {
    totalBytes = sumManifestBytes(manifestJson);
  } catch {
    totalBytes = undefined;
  }

  const valid = await isStagedManifestValid(fs, stagedDirUri, manifestJson);
  return {
    exists: true,
    valid,
    stagedDir: uriToPath(stagedDirUri),
    releaseSha,
    totalBytes,
  };
}

export async function loadCircuitConfig(
  manifestDir: string,
): Promise<CircuitConfig> {
  const fs = await loadExpoFileSystem();
  const manifestDirUri = toFileUri(manifestDir);
  const manifestJson = await fs.readAsStringAsync(`${manifestDirUri}manifest.json`);
  const configArtifact = findManifestArtifact(manifestJson, 'config.json');
  const configJson = await fs.readAsStringAsync(`${manifestDirUri}config.json`);
  const configSha = sha256HexUtf8(configJson);
  if (configSha !== configArtifact.sha256) {
    throw new Error(
      `[zkap-zkp] config.json SHA256 mismatch: expected ${configArtifact.sha256}, got ${configSha}`,
    );
  }
  return normalizeCircuitConfig(JSON.parse(configJson));
}

export async function verify(
  _manifestDir: string,
  _proofOutput: ProofOutput,
): Promise<VerifyOutput> {
  throw new UnsupportedPlatformError(
    'verify',
    'react-native',
    '[zkap-zkp] verify is only available in the Node.js runtime.',
  );
}

// ── Witness generator (independent distribution) ─────────────────────────────
//
// witness_gen.wasm is NOT part of the CRS release. It ships in its own channel
// (a base URL hosting witness_gen.wasm + witness_gen.json). downloadWitnessGen()
// stages both — sidecar first, so a partial wasm can never masquerade as a
// complete cache entry — and returns plain (file://-stripped) paths for prove().
//
// Unlike Node, React Native does NOT re-hash the cached wasm in JS (there is no
// binary-safe JS hashing path here, matching downloadRelease's size-only RN
// validation). It verifies both files exist and are non-empty, and the wasm's
// content SHA256 is enforced fail-closed by the native prove() gate.

const WITNESS_GEN_WASM_NAME = 'witness_gen.wasm';
const WITNESS_GEN_SIDECAR_NAME = 'witness_gen.json';

/** Derive a filesystem-safe, base-URL-keyed cache subdirectory name. */
function witnessGenCacheTag(baseUrl: string): string {
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const safe = cleanBase.replace(/[^a-zA-Z0-9]/g, '_').slice(-56);
  return `zkap-witness-gen-${sha256HexUtf8(cleanBase).slice(0, 16)}-${safe}`;
}

function parseWitnessGenSidecar(sidecarJson: string): WitnessGenSidecar {
  const parsed = JSON.parse(sidecarJson) as unknown;
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as { sha256?: unknown }).sha256 !== 'string'
  ) {
    throw new Error('[zkap-zkp] malformed witness_gen.json: sha256 missing');
  }
  return parsed as WitnessGenSidecar;
}

async function isCachedWitnessGenValid(
  fs: ExpoFileSystem,
  wasmUri: string,
  sidecarUri: string,
): Promise<boolean> {
  try {
    const sidecarSize = await fileSize(fs, sidecarUri);
    if (sidecarSize === undefined) return false;
    const wasmSize = await fileSize(fs, wasmUri);
    if (wasmSize === undefined || wasmSize === 0) return false;
    // Sidecar must parse and declare a sha256 (content SHA is checked at prove time).
    parseWitnessGenSidecar(await fs.readAsStringAsync(sidecarUri));
    return true;
  } catch {
    return false;
  }
}

async function downloadWitnessGenFile(
  fs: ExpoFileSystem,
  url: string,
  destinationUri: string,
  artifact: 'witness_gen.json' | 'witness_gen.wasm',
  onProgress: ((p: DownloadWitnessGenProgress) => void) | undefined,
  signal: AbortSignal | undefined,
): Promise<void> {
  throwIfAborted(signal);
  const task = fs.createDownloadResumable(
    url,
    destinationUri,
    undefined,
    (data) => {
      onProgress?.({
        phase: 'artifact',
        artifact,
        artifactLoadedBytes: data.totalBytesWritten,
        artifactTotalBytes:
          data.totalBytesExpectedToWrite > 0
            ? data.totalBytesExpectedToWrite
            : undefined,
      });
    },
  );

  const onAbort = (): void => {
    void task.cancelAsync();
  };
  signal?.addEventListener('abort', onAbort);
  try {
    await task.downloadAsync();
  } finally {
    signal?.removeEventListener('abort', onAbort);
  }
  throwIfAborted(signal);
}

export async function downloadWitnessGen(
  opts: DownloadWitnessGenOpts,
): Promise<DownloadWitnessGenResult> {
  const fs = await loadExpoFileSystem();
  // Validate fetch availability for parity with downloadRelease, even though the
  // expo downloader performs the network IO.
  getFetch(opts.fetch);
  const signal = opts.signal;
  const baseUrl = opts.baseUrl.replace(/\/+$/, '');
  throwIfAborted(signal);

  const rootUri = toFileUri(
    opts.cacheDir ?? fs.cacheDirectory ?? fs.documentDirectory ?? '',
  );
  if (rootUri === 'file://') {
    throw new Error('[zkap-zkp] no React Native filesystem cache directory is available');
  }
  const dirUri = `${rootUri}${witnessGenCacheTag(baseUrl)}/`;
  const wasmUri = `${dirUri}${WITNESS_GEN_WASM_NAME}`;
  const sidecarUri = `${dirUri}${WITNESS_GEN_SIDECAR_NAME}`;

  if (!opts.force && (await isCachedWitnessGenValid(fs, wasmUri, sidecarUri))) {
    opts.onProgress?.({ phase: 'done' });
    return {
      wasmPath: uriToPath(wasmUri),
      sidecarPath: uriToPath(sidecarUri),
      baseUrl,
    };
  }

  await fs.makeDirectoryAsync(dirUri, { intermediates: true }).catch(
    () => undefined,
  );

  // Sidecar first: a wasm-only partial can never masquerade as a complete entry.
  opts.onProgress?.({ phase: 'metadata', artifact: 'witness_gen.json' });
  await fs.deleteAsync(sidecarUri, { idempotent: true });
  await downloadWitnessGenFile(
    fs,
    `${baseUrl}/${WITNESS_GEN_SIDECAR_NAME}`,
    sidecarUri,
    'witness_gen.json',
    opts.onProgress,
    signal,
  );
  // Parse to fail fast on a malformed sidecar before fetching the (larger) wasm.
  parseWitnessGenSidecar(await fs.readAsStringAsync(sidecarUri));

  await fs.deleteAsync(wasmUri, { idempotent: true });
  await downloadWitnessGenFile(
    fs,
    `${baseUrl}/${WITNESS_GEN_WASM_NAME}`,
    wasmUri,
    'witness_gen.wasm',
    opts.onProgress,
    signal,
  );

  const wasmSize = await fileSize(fs, wasmUri);
  if (wasmSize === undefined || wasmSize === 0) {
    await fs.deleteAsync(wasmUri, { idempotent: true });
    throw new Error('[zkap-zkp] downloaded witness_gen.wasm is missing or empty');
  }

  opts.onProgress?.({ phase: 'done' });
  return {
    wasmPath: uriToPath(wasmUri),
    sidecarPath: uriToPath(sidecarUri),
    baseUrl,
  };
}

export async function getCachedWitnessGenInfo(
  opts: GetCachedWitnessGenInfoOpts,
): Promise<CachedWitnessGenInfo> {
  const fs = await loadExpoFileSystem();
  const baseUrl = opts.baseUrl.replace(/\/+$/, '');
  const rootUri = toFileUri(
    opts.cacheDir ?? fs.cacheDirectory ?? fs.documentDirectory ?? '',
  );
  if (rootUri === 'file://') {
    throw new Error('[zkap-zkp] no React Native filesystem cache directory is available');
  }
  const dirUri = `${rootUri}${witnessGenCacheTag(baseUrl)}/`;
  const wasmUri = `${dirUri}${WITNESS_GEN_WASM_NAME}`;
  const sidecarUri = `${dirUri}${WITNESS_GEN_SIDECAR_NAME}`;

  const exists =
    (await fileSize(fs, wasmUri)) !== undefined &&
    (await fileSize(fs, sidecarUri)) !== undefined;
  if (!exists) {
    return { exists: false, valid: false };
  }

  const valid = await isCachedWitnessGenValid(fs, wasmUri, sidecarUri);
  return {
    exists: true,
    valid,
    wasmPath: uriToPath(wasmUri),
    sidecarPath: uriToPath(sidecarUri),
  };
}
