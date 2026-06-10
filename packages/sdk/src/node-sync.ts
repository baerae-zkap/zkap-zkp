import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { prove as nativeProve } from '@baerae/zkap-zkp-node';
import {
  findManifestArtifact,
  normalizeCircuitConfig,
  sha256HexUtf8,
} from './release-shared';
import { formatMerklePathForCircuit, withFormattedMerklePaths } from './merkle';
import type { CircuitConfig, ProofOutput, ProofRequest } from './types';

export * from './errors';
export { normalizeCircuitConfig } from './release-shared';

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
  verify,
} from '@baerae/zkap-zkp-node';
export { formatMerklePathForCircuit, withFormattedMerklePaths } from './merkle';

/**
 * Synchronous `prove`.
 *
 * Behaviourally mirrors the async `node` facade's Merkle-path handling: the
 * on-chain `getMerklePath()` output carried in each credential's `merklePath`
 * is reordered for the circuit via {@link withFormattedMerklePaths} EXACTLY
 * ONCE here, before the native prover runs. Callers therefore pass the
 * contract path verbatim and MUST NOT also reverse it themselves — a double
 * reverse breaks the issuer-key Merkle-membership constraint
 * (`InvalidProveRequest … issuer-key leaf is not a member of merkle_root`).
 *
 * Unlike the async `node` facade, witness-gen paths are NOT auto-resolved: the
 * caller still supplies `witnessGenPath` (and, if used, `witnessGenSidecarPath`)
 * on the request. This keeps the sync facade a thin, dependency-light
 * passthrough over the native binding.
 */
export function prove(
  config: CircuitConfig,
  request: ProofRequest,
): ProofOutput {
  return nativeProve(
    config,
    withFormattedMerklePaths(request) as Parameters<typeof nativeProve>[1],
  );
}

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
