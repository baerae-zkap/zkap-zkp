import {
  deriveSelector as nativeDeriveSelector,
  generateAnchor as nativeGenerateAnchor,
  generateAudHash as nativeGenerateAudHash,
  generateHash as nativeGenerateHash,
  generateLeafHash as nativeGenerateLeafHash,
  loadRelease as nativeLoadRelease,
  prepareProver as nativePrepareProver,
  prove as nativeProve,
  verify as nativeVerify,
} from '@baerae/zkap-zkp-node';
import type { JsProofOutput } from './types';
import { withFormattedMerklePaths } from './merkle';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
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

export async function initZkap(): Promise<void> {
  return undefined;
}

export async function generateHash(messages: string[]): Promise<string> {
  return nativeGenerateHash(messages);
}

export async function generateAnchor(
  config: CircuitConfig,
  secrets: Secret[],
): Promise<AnchorResult> {
  return nativeGenerateAnchor(config, secrets);
}

export async function deriveSelector(
  config: CircuitConfig,
  secrets: Secret[],
  anchorEvaluations: string[],
): Promise<number[]> {
  return nativeDeriveSelector(config, secrets, anchorEvaluations);
}

export async function generateAudHash(
  config: CircuitConfig,
  audList: string[],
): Promise<AudHashResult> {
  return nativeGenerateAudHash(config, audList);
}

export async function generateLeafHash(
  config: CircuitConfig,
  iss: string,
  pkB64: string,
): Promise<string> {
  return nativeGenerateLeafHash(config, iss, pkB64);
}

/**
 * Resolve the witness-generator paths for `prove()`/`prepareProver()`.
 *
 * - Both omitted → co-located default (`<manifestDir>/witness_gen.wasm` +
 *   `<manifestDir>/witness_gen.json`).
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
  return {
    wasmPath: join(manifestDir, 'witness_gen.wasm'),
    sidecarPath: join(manifestDir, 'witness_gen.json'),
  };
}

export async function prepareProver(
  manifestDir: string,
  witnessGenPath?: string,
  witnessGenSidecarPath?: string,
): Promise<PrepareProverResult> {
  const { wasmPath, sidecarPath } = resolveWitnessGenPaths(
    manifestDir,
    witnessGenPath,
    witnessGenSidecarPath,
  );
  return nativePrepareProver(manifestDir, wasmPath, sidecarPath);
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
  return nativeProve(
    config,
    withFormattedMerklePaths({
      ...request,
      witnessGenPath: wasmPath,
      witnessGenSidecarPath: sidecarPath,
    }) as Parameters<typeof nativeProve>[1],
  );
}

export async function loadRelease(
  opts: LoadReleaseOpts,
): Promise<LoadReleaseResult> {
  return nativeLoadRelease(opts);
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

async function fileSize(path: string): Promise<number | undefined> {
  try {
    return (await stat(path)).size;
  } catch {
    return undefined;
  }
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest('hex');
}

async function readStagedManifest(
  stagedDir: string,
): Promise<string | undefined> {
  try {
    return await readFile(join(stagedDir, 'manifest.json'), 'utf8');
  } catch {
    return undefined;
  }
}

/**
 * Validate a staged directory against its own manifest: every manifest artifact must
 * exist with a matching size and content SHA256. Fully offline — no SHA256SUMS needed.
 */
async function isStagedManifestValid(
  stagedDir: string,
  manifestJson: string,
): Promise<boolean> {
  try {
    for (const artifact of listManifestArtifacts(manifestJson)) {
      const artifactPath = join(stagedDir, artifact.path);
      const actualSize = await fileSize(artifactPath);
      if (actualSize === undefined) return false;
      if (artifact.size !== undefined && actualSize !== artifact.size) {
        return false;
      }
      if ((await sha256File(artifactPath)) !== artifact.sha256) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

async function isCachedReleaseValid(
  stagedDir: string,
  sha256Sums: Map<string, string>,
): Promise<boolean> {
  const manifestJson = await readStagedManifest(stagedDir);
  if (manifestJson === undefined) return false;
  const expectedManifestSha = sha256Sums.get('manifest.json');
  if (
    !expectedManifestSha ||
    sha256HexUtf8(manifestJson) !== expectedManifestSha
  ) {
    return false;
  }
  return isStagedManifestValid(stagedDir, manifestJson);
}

interface ReleaseProgressState {
  /** Bytes already accounted for by fully-completed artifacts. */
  releaseBaseBytes: number;
  /** Total downloaded bytes of the whole release, when known. */
  releaseTotalBytes: number | undefined;
}

async function downloadFile(
  url: string,
  destination: string,
  expectedSha256: string,
  artifactTotalBytes: number | undefined,
  progress: Pick<
    DownloadReleaseProgress,
    'phase' | 'artifact' | 'completedArtifacts' | 'totalArtifacts'
  >,
  releaseState: ReleaseProgressState,
  onProgress: ((progress: DownloadReleaseProgress) => void) | undefined,
  fetchImpl: typeof fetch,
  signal: AbortSignal | undefined,
): Promise<void> {
  throwIfAborted(signal);
  const response = await fetchImpl(url, signal ? { signal } : undefined);
  if (!response.ok) {
    throw new Error(`[zkap-zkp] failed to download ${url}: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new Error(`[zkap-zkp] failed to download ${url}: empty response body`);
  }

  await mkdir(dirname(destination), { recursive: true });
  const headerBytes = Number(response.headers.get('content-length')) || undefined;
  const artifactTotal = artifactTotalBytes ?? headerBytes;
  const hash = createHash('sha256');
  let loadedBytes = 0;

  const meter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      loadedBytes += chunk.byteLength;
      hash.update(chunk);
      const releaseLoadedBytes =
        releaseState.releaseTotalBytes !== undefined
          ? releaseState.releaseBaseBytes + loadedBytes
          : undefined;
      onProgress?.(
        buildArtifactProgress(
          progress,
          loadedBytes,
          artifactTotal,
          releaseLoadedBytes,
          releaseState.releaseTotalBytes,
        ),
      );
      callback(null, chunk);
    },
  });

  await pipeline(
    Readable.fromWeb(response.body as never),
    meter,
    createWriteStream(destination),
  );

  const actualSha256 = hash.digest('hex');
  if (actualSha256 !== expectedSha256.toLowerCase()) {
    await rm(destination, { force: true });
    throw new Error(
      `[zkap-zkp] SHA256 mismatch for ${progress.artifact}: expected ${expectedSha256}, got ${actualSha256}`,
    );
  }

  releaseState.releaseBaseBytes += artifactTotalBytes ?? loadedBytes;
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

  const cacheRoot = opts.cacheDir ?? tmpdir();
  const stagedDir = join(cacheRoot, `zkap-release-${releaseSha}-${shape}`);
  const tmpStagedDir = `${stagedDir}.tmp`;

  if (!opts.force && (await isCachedReleaseValid(stagedDir, sha256Sums))) {
    const manifestJson = await readFile(join(stagedDir, 'manifest.json'), 'utf8');
    return {
      stagedDir,
      manifestJson,
      shape,
      releaseSha,
    };
  }

  await rm(tmpStagedDir, { recursive: true, force: true });
  await mkdir(tmpStagedDir, { recursive: true });

  try {
    const totalArtifacts = RELEASE_ARTIFACT_NAMES.length;
    const expectedManifestSha = sha256Sums.get('manifest.json');
    if (!expectedManifestSha) {
      throw new Error(`[zkap-zkp] ${sha256SumsName} missing manifest.json`);
    }

    // manifest.json is fetched as a small file; whole-release totals are computed from it.
    const releaseState: ReleaseProgressState = {
      releaseBaseBytes: 0,
      releaseTotalBytes: undefined,
    };
    await downloadFile(
      releaseFileUrl(opts.baseUrl, releaseFileName(shape, 'manifest.json')),
      join(tmpStagedDir, 'manifest.json'),
      expectedManifestSha,
      undefined,
      {
        phase: 'artifact',
        artifact: 'manifest.json',
        completedArtifacts: 0,
        totalArtifacts,
      },
      releaseState,
      opts.onProgress,
      fetchImpl,
      signal,
    );
    const manifestJson = await readFile(join(tmpStagedDir, 'manifest.json'), 'utf8');

    // Whole-release total excludes manifest.json: it is already on disk and tiny.
    releaseState.releaseTotalBytes = sumManifestBytes(manifestJson, {
      excludePaths: ['manifest.json'],
    });
    releaseState.releaseBaseBytes = 0;

    let completedArtifacts = 1;

    for (const artifactName of RELEASE_ARTIFACT_NAMES.filter(
      (name) => name !== 'manifest.json',
    )) {
      const expectedSha256 = sha256Sums.get(artifactName);
      if (!expectedSha256) {
        throw new Error(`[zkap-zkp] ${sha256SumsName} missing ${artifactName}`);
      }

      await downloadFile(
        releaseFileUrl(opts.baseUrl, releaseFileName(shape, artifactName)),
        join(tmpStagedDir, artifactName),
        expectedSha256,
        findManifestArtifact(manifestJson, artifactName).size,
        {
          phase: 'artifact',
          artifact: artifactName,
          completedArtifacts,
          totalArtifacts,
        },
        releaseState,
        opts.onProgress,
        fetchImpl,
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
    await rm(stagedDir, { recursive: true, force: true });
    await rename(tmpStagedDir, stagedDir);

    opts.onProgress?.({
      phase: 'done',
      completedArtifacts: totalArtifacts,
      totalArtifacts,
      releaseLoadedBytes: releaseState.releaseTotalBytes,
      releaseTotalBytes: releaseState.releaseTotalBytes,
      percent: releaseState.releaseTotalBytes !== undefined ? 1 : undefined,
    });
    return { stagedDir, manifestJson, shape, releaseSha };
  } catch (error) {
    await rm(tmpStagedDir, { recursive: true, force: true });
    if (signal?.aborted) {
      throw makeAbortError();
    }
    throw error;
  }
}

export async function getCachedReleaseInfo(
  opts: GetCachedReleaseInfoOpts,
): Promise<CachedReleaseInfo> {
  const shape = opts.shape;
  validateReleaseShape(shape);
  const releaseSha = opts.expectedReleaseSha.toLowerCase();
  const cacheRoot = opts.cacheDir ?? tmpdir();
  const stagedDir = join(cacheRoot, `zkap-release-${releaseSha}-${shape}`);

  const manifestJson = await readStagedManifest(stagedDir);
  if (manifestJson === undefined) {
    return { exists: false, valid: false, releaseSha };
  }

  let totalBytes: number | undefined;
  try {
    totalBytes = sumManifestBytes(manifestJson);
  } catch {
    totalBytes = undefined;
  }

  const valid = await isStagedManifestValid(stagedDir, manifestJson);
  return { exists: true, valid, stagedDir, releaseSha, totalBytes };
}

export async function loadCircuitConfig(
  manifestDir: string,
): Promise<CircuitConfig> {
  const manifestJson = await readFile(join(manifestDir, 'manifest.json'), 'utf8');
  const configArtifact = findManifestArtifact(manifestJson, 'config.json');
  const configJson = await readFile(join(manifestDir, 'config.json'), 'utf8');
  const configSha = sha256HexUtf8(configJson);
  if (configSha !== configArtifact.sha256) {
    throw new Error(
      `[zkap-zkp] config.json SHA256 mismatch: expected ${configArtifact.sha256}, got ${configSha}`,
    );
  }
  return normalizeCircuitConfig(JSON.parse(configJson));
}

export async function verify(
  manifestDir: string,
  proofOutput: ProofOutput,
): Promise<VerifyOutput> {
  return nativeVerify(manifestDir, proofOutput as JsProofOutput);
}

// ── Witness generator (independent distribution) ─────────────────────────────
//
// witness_gen.wasm is NOT part of the CRS release. It ships in its own channel
// (a base URL hosting witness_gen.wasm + witness_gen.json). downloadWitnessGen()
// stages both, fail-closed: it fetches the sidecar first so a partial wasm can
// never masquerade as a complete cache entry, then verifies sha256(wasm) against
// the sidecar's `sha256` before returning resolved paths for prove().

const WITNESS_GEN_WASM_NAME = 'witness_gen.wasm';
const WITNESS_GEN_SIDECAR_NAME = 'witness_gen.json';

/** Derive a filesystem-safe, base-URL-keyed cache subdirectory name. */
function witnessGenCacheTag(baseUrl: string): string {
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const safe = cleanBase.replace(/[^a-zA-Z0-9]/g, '_').slice(-56);
  return `zkap-witness-gen-${sha256HexUtf8(cleanBase).slice(0, 16)}-${safe}`;
}

function witnessGenDir(baseUrl: string, cacheDir?: string): string {
  return join(cacheDir ?? tmpdir(), witnessGenCacheTag(baseUrl));
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
  wasmPath: string,
  sidecarPath: string,
): Promise<boolean> {
  try {
    const sidecarJson = await readFile(sidecarPath, 'utf8');
    const sidecar = parseWitnessGenSidecar(sidecarJson);
    if ((await fileSize(wasmPath)) === undefined) return false;
    return (await sha256File(wasmPath)) === sidecar.sha256.toLowerCase();
  } catch {
    return false;
  }
}

async function downloadWitnessGenFile(
  url: string,
  destination: string,
  artifact: 'witness_gen.json' | 'witness_gen.wasm',
  onProgress: ((p: DownloadWitnessGenProgress) => void) | undefined,
  fetchImpl: typeof fetch,
  signal: AbortSignal | undefined,
): Promise<void> {
  throwIfAborted(signal);
  const response = await fetchImpl(url, signal ? { signal } : undefined);
  if (!response.ok) {
    throw new Error(`[zkap-zkp] failed to download ${url}: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new Error(`[zkap-zkp] failed to download ${url}: empty response body`);
  }

  await mkdir(dirname(destination), { recursive: true });
  const artifactTotalBytes =
    Number(response.headers.get('content-length')) || undefined;
  let loadedBytes = 0;

  const meter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      loadedBytes += chunk.byteLength;
      onProgress?.({
        phase: 'artifact',
        artifact,
        artifactLoadedBytes: loadedBytes,
        artifactTotalBytes,
      });
      callback(null, chunk);
    },
  });

  await pipeline(
    Readable.fromWeb(response.body as never),
    meter,
    createWriteStream(destination),
  );
  throwIfAborted(signal);
}

export async function downloadWitnessGen(
  opts: DownloadWitnessGenOpts,
): Promise<DownloadWitnessGenResult> {
  const fetchImpl = getFetch(opts.fetch);
  const signal = opts.signal;
  const baseUrl = opts.baseUrl.replace(/\/+$/, '');
  throwIfAborted(signal);

  const dir = witnessGenDir(baseUrl, opts.cacheDir);
  const wasmPath = join(dir, WITNESS_GEN_WASM_NAME);
  const sidecarPath = join(dir, WITNESS_GEN_SIDECAR_NAME);

  if (!opts.force && (await isCachedWitnessGenValid(wasmPath, sidecarPath))) {
    opts.onProgress?.({ phase: 'done' });
    return { wasmPath, sidecarPath, baseUrl };
  }

  await mkdir(dir, { recursive: true });

  // Sidecar first: a wasm-only partial can never masquerade as a complete entry.
  opts.onProgress?.({ phase: 'metadata', artifact: 'witness_gen.json' });
  await downloadWitnessGenFile(
    `${baseUrl}/${WITNESS_GEN_SIDECAR_NAME}`,
    sidecarPath,
    'witness_gen.json',
    opts.onProgress,
    fetchImpl,
    signal,
  );
  const sidecar = parseWitnessGenSidecar(await readFile(sidecarPath, 'utf8'));

  await downloadWitnessGenFile(
    `${baseUrl}/${WITNESS_GEN_WASM_NAME}`,
    wasmPath,
    'witness_gen.wasm',
    opts.onProgress,
    fetchImpl,
    signal,
  );

  const actualSha256 = await sha256File(wasmPath);
  if (actualSha256 !== sidecar.sha256.toLowerCase()) {
    await rm(wasmPath, { force: true });
    throw new Error(
      `[zkap-zkp] SHA256 mismatch for witness_gen.wasm: expected ${sidecar.sha256}, got ${actualSha256}`,
    );
  }

  opts.onProgress?.({ phase: 'done' });
  return { wasmPath, sidecarPath, baseUrl };
}

export async function getCachedWitnessGenInfo(
  opts: GetCachedWitnessGenInfoOpts,
): Promise<CachedWitnessGenInfo> {
  const baseUrl = opts.baseUrl.replace(/\/+$/, '');
  const dir = witnessGenDir(baseUrl, opts.cacheDir);
  const wasmPath = join(dir, WITNESS_GEN_WASM_NAME);
  const sidecarPath = join(dir, WITNESS_GEN_SIDECAR_NAME);

  const exists =
    (await fileSize(wasmPath)) !== undefined &&
    (await fileSize(sidecarPath)) !== undefined;
  if (!exists) {
    return { exists: false, valid: false };
  }

  const valid = await isCachedWitnessGenValid(wasmPath, sidecarPath);
  return { exists: true, valid, wasmPath, sidecarPath };
}
