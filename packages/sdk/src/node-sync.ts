import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  findManifestArtifact,
  normalizeCircuitConfig,
  sha256HexUtf8,
} from './release-shared';
import type { CircuitConfig } from './types';

export * from './errors';
export { ZKAP_CIRCUIT_COMMIT, normalizeCircuitConfig } from './release-shared';

export type {
  AnchorResult,
  AudHashResult,
  CircuitConfig,
  LoadReleaseOpts,
  LoadReleaseResult,
  ParallelProveComparison,
  PrepareProverResult,
  PrepareProverTiming,
  ProofOutput,
  ProofRequest,
  ProveCredential,
  ProveTiming,
  Secret,
  VerifyOutput,
  JsAnchorResult,
  JsAudHashResult,
  JsCircuitConfig,
  JsLoadReleaseOpts,
  JsLoadReleaseResult,
  JsParallelProveComparison,
  JsPrepareProverResult,
  JsPrepareProverTiming,
  JsProofOutput,
  JsProofRequest,
  JsProveCredential,
  JsProveTiming,
  JsSecret,
  JsVerifyOutput,
} from './types';

export {
  generateAnchor,
  generateAudHash,
  generateHash,
  generateLeafHash,
  loadRelease,
  prepareProver,
  prove,
  verify,
} from '@baerae/zkap-zkp-sdk-node';

export function initZkap(): void {
  return undefined;
}

export function loadCircuitConfig(manifestDir: string): CircuitConfig {
  const manifestJson = readFileSync(join(manifestDir, 'manifest.json'), 'utf8');
  const configArtifact = findManifestArtifact(manifestJson, 'config.json');
  const configJson = readFileSync(join(manifestDir, 'config.json'), 'utf8');
  const configSha = sha256HexUtf8(configJson);
  if (configSha !== configArtifact.sha256) {
    throw new Error(
      `[zkap-zkp] config.json SHA256 mismatch: expected ${configArtifact.sha256}, got ${configSha}`,
    );
  }
  return normalizeCircuitConfig(JSON.parse(configJson));
}
