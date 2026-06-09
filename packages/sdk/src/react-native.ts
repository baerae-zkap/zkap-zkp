import {
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
  computeReleaseSha,
  findManifestArtifact,
  listManifestArtifacts,
  normalizeCircuitConfig,
  parseSha256Sums,
  releaseFileName,
  releaseFileUrl,
  sha256HexUtf8,
  validateReleaseShape,
} from './release-shared';
import type {
  AnchorResult,
  AudHashResult,
  CircuitConfig,
  DownloadReleaseOpts,
  DownloadReleaseProgress,
  DownloadReleaseResult,
  LoadReleaseOpts,
  LoadReleaseResult,
  PrepareProverResult,
  ProofOutput,
  ProofRequest,
  Secret,
  VerifyOutput,
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
  _witnessGenPath: string,
  _witnessGenSidecarPath: string,
): Promise<PrepareProverResult> {
  throw new UnsupportedPlatformError(
    'prepareProver',
    'react-native',
    '[zkap-zkp] prepareProver is only available in the Node.js runtime.',
  );
}

export async function prove(
  config: CircuitConfig,
  request: ProofRequest,
): Promise<ProofOutput> {
  const result = await rnProve(
    toReactNativeConfig(config),
    withFormattedMerklePaths(request) as unknown as ReactNativeProofRequest,
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

const EXPO_FILE_SYSTEM_LEGACY_MODULE = 'expo-file-system/legacy';

interface ExpoFileInfo {
  exists: boolean;
  isDirectory?: boolean;
  size?: number;
}

interface ExpoFileSystem {
  cacheDirectory?: string | null;
  documentDirectory?: string | null;
  deleteAsync(uri: string, options?: { idempotent?: boolean }): Promise<void>;
  downloadAsync(url: string, fileUri: string): Promise<unknown>;
  getInfoAsync(fileUri: string): Promise<ExpoFileInfo>;
  makeDirectoryAsync(uri: string, options?: { intermediates?: boolean }): Promise<void>;
  moveAsync(options: { from: string; to: string }): Promise<void>;
  readAsStringAsync(fileUri: string): Promise<string>;
  writeAsStringAsync(fileUri: string, contents: string): Promise<void>;
}

async function loadExpoFileSystem(): Promise<ExpoFileSystem> {
  try {
    return (await import(EXPO_FILE_SYSTEM_LEGACY_MODULE)) as ExpoFileSystem;
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
): Promise<string> {
  const response = await fetchImpl(url);
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

async function isCachedReleaseValid(
  fs: ExpoFileSystem,
  stagedDirUri: string,
  sha256Sums: Map<string, string>,
): Promise<boolean> {
  try {
    const manifestJson = await fs.readAsStringAsync(`${stagedDirUri}manifest.json`);
    const expectedManifestSha = sha256Sums.get('manifest.json');
    if (
      !expectedManifestSha ||
      sha256HexUtf8(manifestJson) !== expectedManifestSha
    ) {
      return false;
    }

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

async function downloadFile(
  fs: ExpoFileSystem,
  url: string,
  destinationUri: string,
  expectedBytes: number | undefined,
  progress: Omit<DownloadReleaseProgress, 'loadedBytes' | 'totalBytes'>,
  onProgress: ((progress: DownloadReleaseProgress) => void) | undefined,
): Promise<void> {
  await fs.downloadAsync(url, destinationUri);
  const actualSize = await fileSize(fs, destinationUri);
  if (expectedBytes !== undefined && actualSize !== expectedBytes) {
    await fs.deleteAsync(destinationUri, { idempotent: true });
    throw new Error(
      `[zkap-zkp] downloaded artifact has invalid size for ${progress.artifact}: expected ${expectedBytes}, got ${actualSize ?? 'missing'}`,
    );
  }
  onProgress?.({
    ...progress,
    loadedBytes: actualSize,
    totalBytes: expectedBytes,
  });
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
  const shape = opts.shape;
  validateReleaseShape(shape);
  const sha256SumsName = `${shape}-SHA256SUMS`;
  const sha256SumsUrl = releaseFileUrl(opts.baseUrl, sha256SumsName);

  opts.onProgress?.({ phase: 'metadata', artifact: sha256SumsName });
  const sha256SumsText = await fetchText(sha256SumsUrl, fetchImpl);
  const releaseSha = computeReleaseSha(sha256SumsText);
  assertReleaseSha(releaseSha, opts.expectedReleaseSha);
  const sha256Sums = parseSha256Sums(sha256SumsText);

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

  const expectedManifestSha = sha256Sums.get('manifest.json');
  if (!expectedManifestSha) {
    throw new Error(`[zkap-zkp] ${sha256SumsName} missing manifest.json`);
  }
  const manifestJson = await fetchText(
    releaseFileUrl(opts.baseUrl, releaseFileName(shape, 'manifest.json')),
    fetchImpl,
  );
  const manifestSha = sha256HexUtf8(manifestJson);
  if (manifestSha !== expectedManifestSha) {
    throw new Error(
      `[zkap-zkp] manifest.json SHA256 mismatch: expected ${expectedManifestSha}, got ${manifestSha}`,
    );
  }
  await fs.writeAsStringAsync(`${tmpStagedDirUri}manifest.json`, manifestJson);

  const totalArtifacts = RELEASE_ARTIFACT_NAMES.length;
  let completedArtifacts = 1;
  opts.onProgress?.({
    phase: 'artifact',
    artifact: 'manifest.json',
    completedArtifacts: 0,
    totalArtifacts,
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
      opts.onProgress,
    );
    completedArtifacts += 1;
  }

  opts.onProgress?.({ phase: 'stage', completedArtifacts: totalArtifacts, totalArtifacts });
  await fs.deleteAsync(stagedDirUri, { idempotent: true });
  await fs.moveAsync({ from: tmpStagedDirUri, to: stagedDirUri });
  opts.onProgress?.({ phase: 'done', completedArtifacts: totalArtifacts, totalArtifacts });

  return { stagedDir: uriToPath(stagedDirUri), manifestJson, shape, releaseSha };
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
