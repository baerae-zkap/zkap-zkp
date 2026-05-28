import {
  generateAnchor as nativeGenerateAnchor,
  generateAudHash as nativeGenerateAudHash,
  generateHash as nativeGenerateHash,
  generateLeafHash as nativeGenerateLeafHash,
  loadRelease as nativeLoadRelease,
  prepareProver as nativePrepareProver,
  prove as nativeProve,
  verify as nativeVerify,
} from '@baerae/zkap-zkp-node';
import type { JsProofOutput } from '@baerae/zkap-zkp-node';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  RELEASE_ARTIFACT_NAMES,
  WITNESS_GEN_NAME,
  assertManifestCircuitCommit,
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
export { ZKAP_CIRCUIT_COMMIT, normalizeCircuitConfig } from './release-shared';

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

export async function prepareProver(
  manifestDir: string,
): Promise<PrepareProverResult> {
  return nativePrepareProver(manifestDir);
}

export async function prove(
  config: CircuitConfig,
  request: ProofRequest,
): Promise<ProofOutput> {
  return nativeProve(config, request);
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
): Promise<string> {
  const response = await fetchImpl(url);
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

async function isCachedReleaseValid(
  stagedDir: string,
  sha256Sums: Map<string, string>,
): Promise<boolean> {
  try {
    const manifestJson = await readFile(join(stagedDir, 'manifest.json'), 'utf8');
    const expectedManifestSha = sha256Sums.get('manifest.json');
    if (
      !expectedManifestSha ||
      sha256HexUtf8(manifestJson) !== expectedManifestSha
    ) {
      return false;
    }
    findManifestArtifact(manifestJson, WITNESS_GEN_NAME);

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

async function downloadFile(
  url: string,
  destination: string,
  expectedSha256: string,
  progress: Omit<DownloadReleaseProgress, 'loadedBytes' | 'totalBytes'>,
  onProgress: ((progress: DownloadReleaseProgress) => void) | undefined,
  fetchImpl: typeof fetch,
): Promise<void> {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`[zkap-zkp] failed to download ${url}: HTTP ${response.status}`);
  }
  if (!response.body) {
    throw new Error(`[zkap-zkp] failed to download ${url}: empty response body`);
  }

  await mkdir(dirname(destination), { recursive: true });
  const expectedBytes = Number(response.headers.get('content-length')) || undefined;
  const hash = createHash('sha256');
  let loadedBytes = 0;

  const meter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      loadedBytes += chunk.byteLength;
      hash.update(chunk);
      onProgress?.({
        ...progress,
        loadedBytes,
        totalBytes: expectedBytes,
      });
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
  const shape = opts.shape;
  validateReleaseShape(shape);
  const sha256SumsName = `${shape}-SHA256SUMS`;
  const sha256SumsUrl = releaseFileUrl(opts.baseUrl, sha256SumsName);

  opts.onProgress?.({ phase: 'metadata', artifact: sha256SumsName });
  const sha256SumsText = await fetchText(sha256SumsUrl, fetchImpl);
  const releaseSha = computeReleaseSha(sha256SumsText);
  assertReleaseSha(releaseSha, opts.expectedReleaseSha);
  const sha256Sums = parseSha256Sums(sha256SumsText);

  const cacheRoot = opts.cacheDir ?? tmpdir();
  const stagedDir = join(cacheRoot, `zkap-release-${releaseSha}-${shape}`);
  const tmpStagedDir = `${stagedDir}.tmp`;

  if (!opts.force && (await isCachedReleaseValid(stagedDir, sha256Sums))) {
    const manifestJson = await readFile(join(stagedDir, 'manifest.json'), 'utf8');
    assertManifestCircuitCommit(manifestJson, opts);
    return {
      stagedDir,
      manifestJson,
      shape,
      releaseSha,
    };
  }

  await rm(tmpStagedDir, { recursive: true, force: true });
  await mkdir(tmpStagedDir, { recursive: true });

  const totalArtifacts = RELEASE_ARTIFACT_NAMES.length + 1;
  const expectedManifestSha = sha256Sums.get('manifest.json');
  if (!expectedManifestSha) {
    throw new Error(`[zkap-zkp] ${sha256SumsName} missing manifest.json`);
  }
  await downloadFile(
    releaseFileUrl(opts.baseUrl, releaseFileName(shape, 'manifest.json')),
    join(tmpStagedDir, 'manifest.json'),
    expectedManifestSha,
    {
      phase: 'artifact',
      artifact: 'manifest.json',
      completedArtifacts: 0,
      totalArtifacts,
    },
    opts.onProgress,
    fetchImpl,
  );
  const manifestJson = await readFile(join(tmpStagedDir, 'manifest.json'), 'utf8');
  assertManifestCircuitCommit(manifestJson, opts);

  let completedArtifacts = 1;

  for (const artifactName of RELEASE_ARTIFACT_NAMES.filter(
    (name) => name !== 'manifest.json',
  )) {
    const expectedSha256 = sha256Sums.get(artifactName);
    if (!expectedSha256) {
      throw new Error(
        `[zkap-zkp] ${sha256SumsName} missing ${artifactName}`,
      );
    }

    await downloadFile(
      releaseFileUrl(opts.baseUrl, releaseFileName(shape, artifactName)),
      join(tmpStagedDir, artifactName),
      expectedSha256,
      {
        phase: 'artifact',
        artifact: artifactName,
        completedArtifacts,
        totalArtifacts,
      },
      opts.onProgress,
      fetchImpl,
    );
    completedArtifacts += 1;
  }

  const witnessGen = findManifestArtifact(manifestJson, WITNESS_GEN_NAME);
  await downloadFile(
    releaseFileUrl(opts.baseUrl, WITNESS_GEN_NAME),
    join(tmpStagedDir, WITNESS_GEN_NAME),
    witnessGen.sha256,
    {
      phase: 'artifact',
      artifact: WITNESS_GEN_NAME,
      completedArtifacts,
      totalArtifacts,
    },
    opts.onProgress,
    fetchImpl,
  );

  opts.onProgress?.({ phase: 'stage', completedArtifacts: totalArtifacts, totalArtifacts });
  await rm(stagedDir, { recursive: true, force: true });
  await rename(tmpStagedDir, stagedDir);

  opts.onProgress?.({ phase: 'done', completedArtifacts: totalArtifacts, totalArtifacts });
  return { stagedDir, manifestJson, shape, releaseSha };
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
