import initWasm, {
  deriveSelector as wasmDeriveSelector,
  generateAnchor as wasmGenerateAnchor,
  generateAudHash as wasmGenerateAudHash,
  generateHash as wasmGenerateHash,
  generateLeafHash as wasmGenerateLeafHash,
} from '@baerae/zkap-zkp-wasm';
import { UnsupportedPlatformError } from './errors';
import type {
  AnchorResult,
  AudHashResult,
  CachedReleaseInfo,
  CircuitConfig,
  DownloadReleaseOpts,
  DownloadReleaseResult,
  GetCachedReleaseInfoOpts,
  InitInput,
  InitOutput,
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

let wasmReady: Promise<InitOutput> | undefined;

export function initZkap(moduleOrPath?: InitInput): Promise<InitOutput> {
  if (!wasmReady) {
    wasmReady = initWasm(moduleOrPath).catch((error) => {
      wasmReady = undefined;
      throw error;
    });
  }
  return wasmReady;
}

async function ensureWasmInitialized(): Promise<void> {
  await initZkap();
}

export async function generateHash(messages: string[]): Promise<string> {
  await ensureWasmInitialized();
  return wasmGenerateHash(messages);
}

export async function generateAnchor(
  config: CircuitConfig,
  secrets: Secret[],
): Promise<AnchorResult> {
  await ensureWasmInitialized();
  return wasmGenerateAnchor(config, secrets);
}

export async function deriveSelector(
  config: CircuitConfig,
  secrets: Secret[],
  anchorEvaluations: string[],
): Promise<number[]> {
  await ensureWasmInitialized();
  return wasmDeriveSelector(config, secrets, anchorEvaluations);
}

export async function generateAudHash(
  config: CircuitConfig,
  audList: string[],
): Promise<AudHashResult> {
  await ensureWasmInitialized();
  return wasmGenerateAudHash(config, audList);
}

export async function generateLeafHash(
  config: CircuitConfig,
  iss: string,
  pkB64: string,
): Promise<string> {
  await ensureWasmInitialized();
  return wasmGenerateLeafHash(config, iss, pkB64);
}

export async function prepareProver(
  _manifestDir: string,
): Promise<PrepareProverResult> {
  throw new UnsupportedPlatformError(
    'prepareProver',
    'wasm',
    '[zkap-zkp] prepareProver is only available in the Node.js runtime.',
  );
}

export async function prove(
  _config: CircuitConfig,
  _request: ProofRequest,
): Promise<ProofOutput> {
  throw new UnsupportedPlatformError(
    'prove',
    'wasm',
    '[zkap-zkp] prove is not available in WebAssembly. Use Node.js for server-side proving or React Native for on-device proving.',
  );
}

export async function loadRelease(
  _opts: LoadReleaseOpts,
): Promise<LoadReleaseResult> {
  throw new UnsupportedPlatformError(
    'loadRelease',
    'wasm',
    '[zkap-zkp] loadRelease is only available in the Node.js runtime.',
  );
}

export async function downloadRelease(
  _opts: DownloadReleaseOpts,
): Promise<DownloadReleaseResult> {
  throw new UnsupportedPlatformError(
    'downloadRelease',
    'wasm',
    '[zkap-zkp] downloadRelease is not available in WebAssembly because browsers cannot provide a local manifestDir for prove(). Use Node.js or React Native.',
  );
}

export async function getCachedReleaseInfo(
  _opts: GetCachedReleaseInfoOpts,
): Promise<CachedReleaseInfo> {
  throw new UnsupportedPlatformError(
    'getCachedReleaseInfo',
    'wasm',
    '[zkap-zkp] getCachedReleaseInfo requires filesystem access and is only available in Node.js and React Native.',
  );
}

export async function loadCircuitConfig(
  _manifestDir: string,
): Promise<CircuitConfig> {
  throw new UnsupportedPlatformError(
    'loadCircuitConfig',
    'wasm',
    '[zkap-zkp] loadCircuitConfig requires filesystem access and is only available in Node.js and React Native.',
  );
}

export async function verify(
  _manifestDir: string,
  _proofOutput: ProofOutput,
): Promise<VerifyOutput> {
  throw new UnsupportedPlatformError(
    'verify',
    'wasm',
    '[zkap-zkp] verify is only available in the Node.js runtime.',
  );
}
