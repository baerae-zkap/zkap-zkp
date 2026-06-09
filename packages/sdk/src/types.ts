export interface JsSecret {
  sub: string;
  iss: string;
  aud: string;
}

export interface JsCircuitConfig {
  maxJwtB64Len: number;
  maxPayloadB64Len: number;
  maxAudLen: number;
  maxExpLen: number;
  maxIssLen: number;
  maxNonceLen: number;
  maxSubLen: number;
  n: number;
  k: number;
  treeHeight: number;
  numAudienceLimit: number;
  claims: string[];
  forbiddenString: string;
}

export interface JsAnchorResult {
  evaluations: string[];
}

export interface JsAudHashResult {
  audHashes: string[];
  hAudList: string;
}

export interface JsProveCredential {
  jwt: string;
  rsaModulusB64: string;
  merklePath: string[];
  merkleLeafIdx: number;
}

export interface JsProofRequest {
  manifestDir: string;
  /**
   * Absolute path to the app-fetched `witness_gen.wasm`, distributed
   * independently of the CRS bundle and verified against the sidecar
   * (`witnessGenSidecarPath`) + the CRS `ar1cs_blake3` before use.
   */
  witnessGenPath: string;
  /** Absolute path to the app-fetched `witness_gen.json` sidecar. */
  witnessGenSidecarPath: string;
  random: string;
  hSignUserOp: string;
  anchor: string[];
  merkleRoot: string;
  credentials: JsProveCredential[];
}

export interface JsParallelProveComparison {
  sequentialProveMs: number;
  sequentialPeakRssMb?: number;
  sequentialPeakRssDeltaMb?: number;
  parallelProveMs: number;
  parallelPeakRssMb?: number;
  parallelPeakRssDeltaMb?: number;
  proveMsDelta: number;
  peakRssMbDelta?: number;
}

export interface JsProveTiming {
  loadMs: number;
  synthesizeMs: number;
  proveMs: number;
  totalMs: number;
  backend: string;
  proofMode: string;
  proofPeakRssMb?: number;
  proofPeakRssDeltaMb?: number;
  wasmInstantiateMs?: number;
  wasmCallMs?: number;
  witnessDeserializeMs?: number;
  parallelComparison?: JsParallelProveComparison;
}

export interface JsProofOutput {
  proofs: string[][];
  sharedInputs: string[];
  partialRhsList: string[];
  jwtExpList: string[];
  timing: JsProveTiming;
}

export interface JsPrepareProverTiming {
  totalMs: number;
  manifestMs: number;
  artifactLoadMs: number;
  ar1CsMs: number;
  pkMs: number;
  vkMs: number;
  pvkMs: number;
  circuitConfigMs: number;
  evmVerifierMs: number;
  witnessGenWasmMs: number;
  preparedMs: number;
  wasmCompileMs: number;
}

export interface JsPrepareProverResult {
  loadMs: number;
  cached: boolean;
  timing?: JsPrepareProverTiming;
}

export interface JsLoadReleaseOpts {
  releaseDir: string;
  shape: string;
}

export interface JsLoadReleaseResult {
  stagedDir: string;
  manifestJson: string;
  shape: string;
  releaseSha: string;
}

export interface JsVerifyOutput {
  results: boolean[];
  allValid: boolean;
}

export type WasmInitInput =
  | RequestInfo
  | URL
  | Response
  | BufferSource
  | WebAssembly.Module;

export interface WasmInitOutput {
  readonly memory: WebAssembly.Memory;
  readonly generateAnchor: (a: number, b: number, c: number) => void;
  readonly generateAudHash: (a: number, b: number, c: number, d: number) => void;
  readonly generateHash: (a: number, b: number, c: number) => void;
  readonly generateLeafHash: (
    a: number,
    b: number,
    c: number,
    d: number,
    e: number,
    f: number,
  ) => void;
  readonly groth16Setup: (a: number) => void;
  readonly prove: (a: number) => void;
  readonly verify: (a: number) => void;
}

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
