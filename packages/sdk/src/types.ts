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
  /**
   * Merkle authentication path as returned by the on-chain
   * `getMerklePath()` (bottom→root: `[leafSibling, inner_1, …, inner_top]`),
   * passed verbatim. `prove()` reorders it into the circuit's expected order
   * via `formatMerklePathForCircuit` — do NOT reorder it yourself.
   */
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
  /** Name of the artifact currently being downloaded, when `phase` is `"artifact"`. */
  artifact?: string;
  /**
   * Bytes loaded for the **current artifact**.
   * @deprecated Ambiguous name kept for backwards compatibility. Use `artifactLoadedBytes`
   * for per-artifact progress or `releaseLoadedBytes`/`percent` for whole-release progress.
   */
  loadedBytes?: number;
  /**
   * Total bytes of the **current artifact**, when known.
   * @deprecated Ambiguous name kept for backwards compatibility. Use `artifactTotalBytes`
   * for the per-artifact total or `releaseTotalBytes` for the whole-release total.
   */
  totalBytes?: number;
  /** Bytes downloaded so far for the current artifact. */
  artifactLoadedBytes?: number;
  /** Total bytes of the current artifact, when known. */
  artifactTotalBytes?: number;
  /** Bytes downloaded so far across the whole release. Monotonically increasing. */
  releaseLoadedBytes?: number;
  /** Total bytes of the whole release (sum of downloaded manifest artifact sizes), when known. */
  releaseTotalBytes?: number;
  /** Number of artifacts fully downloaded. */
  completedArtifacts?: number;
  /** Total number of artifacts in the release. */
  totalArtifacts?: number;
  /** Whole-release progress in `[0, 1]`, present only when `releaseTotalBytes` is known. */
  percent?: number;
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
  /**
   * Optional abort signal. When aborted, the in-flight download is cancelled, the
   * staging temp directory is removed, and the returned promise rejects with an
   * `AbortError`. Already-staged cache directories are left intact.
   */
  signal?: AbortSignal;
}

export type DownloadReleaseResult = LoadReleaseResult;

export interface GetCachedReleaseInfoOpts {
  /** Cache root. Defaults to `os.tmpdir()` on Node and app cache on React Native. */
  cacheDir?: string;
  /** Release shape, for example `"1-of-1"` or `"3-of-3"`. */
  shape: ReleaseShape;
  /**
   * Pinned first-16 SHA256 of `<shape>-SHA256SUMS`. Required to locate the staged
   * directory without any network request.
   */
  expectedReleaseSha: string;
}

export interface CachedReleaseInfo {
  /** A staged directory for this `(releaseSha, shape)` exists. */
  exists: boolean;
  /**
   * The staged directory passes integrity checks and can be used by `prove()`.
   * On Node this re-verifies each artifact's content SHA256 against the manifest;
   * on React Native it verifies each artifact's size against the manifest.
   */
  valid: boolean;
  /** Absolute path to the staged directory, present when `exists` is `true`. */
  stagedDir?: string;
  /** The release SHA the lookup was performed for. */
  releaseSha?: string;
  /** Total bytes of the staged release (sum of manifest artifact sizes), when known. */
  totalBytes?: number;
}

export interface ProofOutput {
  proofs: string[][];
  sharedInputs: string[];
  partialRhsList: string[];
  jwtExpList: string[];
  timing?: ProveTiming;
}
