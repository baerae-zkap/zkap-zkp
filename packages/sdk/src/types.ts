import type {
  JsAnchorResult,
  JsAudHashResult,
  JsCircuitConfig,
  JsLoadReleaseOpts,
  JsLoadReleaseResult,
  JsParallelProveComparison,
  JsPrepareProverResult,
  JsPrepareProverTiming,
  JsProofRequest,
  JsProofOutput,
  JsProveCredential,
  JsProveTiming,
  JsSecret,
  JsVerifyOutput,
} from '@baerae/zkap-zkp-node';
import type {
  InitInput as WasmInitInput,
  InitOutput as WasmInitOutput,
} from '@baerae/zkap-zkp-wasm';

export type Secret = JsSecret;
export type CircuitConfig = JsCircuitConfig;
export type AnchorResult = JsAnchorResult;
export type AudHashResult = JsAudHashResult;
export type ProveCredential = JsProveCredential;
export type ProofRequest = JsProofRequest;
export type ProveTiming = JsProveTiming;
export type ParallelProveComparison = JsParallelProveComparison;
export type PrepareProverResult = JsPrepareProverResult;
export type PrepareProverTiming = JsPrepareProverTiming;
export type LoadReleaseOpts = JsLoadReleaseOpts;
export type LoadReleaseResult = JsLoadReleaseResult;
export type VerifyOutput = JsVerifyOutput;
export type InitInput = WasmInitInput;
export type InitOutput = WasmInitOutput;

export type ReleaseShape = '1-of-1' | '3-of-3' | (string & {});

export interface DownloadReleaseProgress {
  phase: 'metadata' | 'artifact' | 'stage' | 'done';
  artifact?: string;
  loadedBytes?: number;
  totalBytes?: number;
  completedArtifacts?: number;
  totalArtifacts?: number;
}

export interface DownloadReleaseOpts {
  /** Base URL of a flat zkap-circuit release bundle. */
  baseUrl: string;
  /** Release shape to download, for example `"1-of-1"` or `"3-of-3"`. */
  shape: ReleaseShape;
  /** Optional cache root. Defaults to `os.tmpdir()` on Node and app cache on React Native. */
  cacheDir?: string;
  /** Optional pinned first-16 SHA256 of `<shape>-SHA256SUMS`. */
  expectedReleaseSha?: string;
  /**
   * Optional expected `manifest.build.circuit_commit`.
   *
   * Defaults to the zkap-circuit revision this SDK was built against. Full
   * 40-character commits and unambiguous prefixes of at least 7 characters are
   * accepted.
   */
  expectedCircuitCommit?: string;
  /**
   * Skip `manifest.build.circuit_commit` validation.
   *
   * Intended only for local development bundles that are known to be compatible.
   */
  allowCircuitCommitMismatch?: boolean;
  /** Re-download even when a cached manifest directory appears usable. */
  force?: boolean;
  /** Fetch implementation override for tests or custom networking. */
  fetch?: typeof fetch;
  /** Progress callback for metadata, per-artifact download, and staging. */
  onProgress?: (progress: DownloadReleaseProgress) => void;
}

export type DownloadReleaseResult = LoadReleaseResult;

export interface ProofOutput {
  proofs: string[][];
  sharedInputs: string[];
  partialRhsList: string[];
  jwtExpList: string[];
  timing?: ProveTiming;
}

export type {
  JsSecret,
  JsCircuitConfig,
  JsAnchorResult,
  JsAudHashResult,
  JsProveCredential,
  JsProofRequest,
  JsProofOutput,
  JsProveTiming,
  JsParallelProveComparison,
  JsPrepareProverResult,
  JsPrepareProverTiming,
  JsLoadReleaseOpts,
  JsLoadReleaseResult,
  JsVerifyOutput,
};
