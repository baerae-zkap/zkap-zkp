import NativeZkapReactNative from './NativeZkapReactNative';
import { Platform } from 'react-native';
import generatedBindings, {
  deriveSelector as nativeDeriveSelector,
  generateAnchor as nativeGenerateAnchor,
  generateAudHash as nativeGenerateAudHash,
  generateHash as nativeGenerateHash,
  generateLeafHash as nativeGenerateLeafHash,
  prepareWitnessInputs as nativePrepareWitnessInputs,
  prove as nativeProve,
  proveFromWitnessBundleFile as nativeProveFromWitnessBundleFile,
  type ZkapCircuitConfig,
  type ZkapPreparedWitnessInputs,
  type ZkapProofRequest,
  type ZkapProveCredential,
  type ZkapWitnessBundleFile,
} from './generated/zkap_uniffi_bindings';

// ──────────────────────────────────────────────────────────────────
// Input / Output types
// ──────────────────────────────────────────────────────────────────

export interface CircuitConfig {
  max_jwt_b64_len: number;
  max_payload_b64_len: number;
  max_aud_len: number;
  max_exp_len: number;
  max_iss_len: number;
  max_nonce_len: number;
  max_sub_len: number;
  n: number;
  k: number;
  tree_height: number;
  num_audience_limit: number;
  claims: string[];
  forbidden_string: string;
}

export interface Secret {
  sub: string;
  iss: string;
  aud: string;
}

export interface ProveCredential {
  jwt: string;
  rsa_modulus_b64?: string;
  rsaModulusB64?: string;
  merkle_path?: string[];
  merklePath?: string[];
  merkle_leaf_idx?: number;
  merkleLeafIdx?: number;
}

export interface ProveRequest {
  manifest_dir?: string;
  manifestDir?: string;
  /**
   * Absolute path to the app-fetched `witness_gen.wasm`, distributed
   * independently of the CRS bundle. Verified against the sidecar
   * (`witness_gen_sidecar_path`) and the CRS `ar1cs_blake3` before use.
   */
  witness_gen_path?: string;
  witnessGenPath?: string;
  /** Absolute path to the app-fetched `witness_gen.json` sidecar. */
  witness_gen_sidecar_path?: string;
  witnessGenSidecarPath?: string;
  random: string;
  h_sign_user_op?: string;
  hSignUserOp?: string;
  anchor: string[];
  merkle_root?: string;
  merkleRoot?: string;
  credentials: ProveCredential[];
}

export interface ProveResult {
  /** Solidity-compatible proof per proof: [ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy] */
  proofs: string[][];
  /** Public inputs shared across all JWTs as decimal strings. */
  shared_inputs: string[];
  /** partial_rhs per JWT as decimal string. */
  partial_rhs_list: string[];
  /** jwt_exp per JWT as decimal string. */
  jwt_exp_list: string[];
}

let initialized = false;
const IOS_WITNESS_CHUNK_SIZE = 4 * 1024 * 1024;

function ensureInitialized(): void {
  if (initialized) return;
  NativeZkapReactNative.installRustCrate();
  generatedBindings.initialize();
  initialized = true;
}

type ZkapUniFfiError = Error & {
  tag?: string;
  inner?: {
    message?: string;
  };
};

function withZkapErrorMessage<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    const zkapError = error as ZkapUniFfiError;
    const message = zkapError?.inner?.message;
    if (typeof message === 'string' && message.length > 0) {
      const wrapped = new Error(message);
      wrapped.name = zkapError.tag
        ? `ZkapError.${zkapError.tag}`
        : zkapError.name || 'ZkapError';
      (wrapped as Error & { cause?: unknown }).cause = error;
      throw wrapped;
    }
    throw error;
  }
}

function toNativeConfig(config: CircuitConfig): ZkapCircuitConfig {
  return {
    maxJwtB64Len: BigInt(config.max_jwt_b64_len),
    maxPayloadB64Len: BigInt(config.max_payload_b64_len),
    maxAudLen: BigInt(config.max_aud_len),
    maxExpLen: BigInt(config.max_exp_len),
    maxIssLen: BigInt(config.max_iss_len),
    maxNonceLen: BigInt(config.max_nonce_len),
    maxSubLen: BigInt(config.max_sub_len),
    n: BigInt(config.n),
    k: BigInt(config.k),
    treeHeight: BigInt(config.tree_height),
    numAudienceLimit: BigInt(config.num_audience_limit),
    claims: config.claims,
    forbiddenString: config.forbidden_string,
  };
}

function requireString(value: string | undefined, field: string): string {
  if (!value) {
    throw new Error(`[zkap/sdk-react-native] missing ${field}`);
  }
  return value;
}

function requireArray<T>(value: T[] | undefined, field: string): T[] {
  if (!value) {
    throw new Error(`[zkap/sdk-react-native] missing ${field}`);
  }
  return value;
}

function requireNumber(value: number | undefined, field: string): number {
  if (value === undefined || value === null) {
    throw new Error(`[zkap/sdk-react-native] missing ${field}`);
  }
  return value;
}

function toNativeCredential(credential: ProveCredential): ZkapProveCredential {
  return {
    jwt: credential.jwt,
    rsaModulusB64: requireString(
      credential.rsa_modulus_b64 ?? credential.rsaModulusB64,
      'credential.rsa_modulus_b64',
    ),
    merklePath: requireArray(
      credential.merkle_path ?? credential.merklePath,
      'credential.merkle_path',
    ),
    merkleLeafIdx: BigInt(
      requireNumber(
        credential.merkle_leaf_idx ?? credential.merkleLeafIdx,
        'credential.merkle_leaf_idx',
      ),
    ),
  };
}

function toNativeRequest(request: ProveRequest): ZkapProofRequest {
  return {
    manifestDir: requireString(
      request.manifest_dir ?? request.manifestDir,
      'manifest_dir',
    ),
    witnessGenPath: requireString(
      request.witness_gen_path ?? request.witnessGenPath,
      'witness_gen_path',
    ),
    witnessGenSidecarPath: requireString(
      request.witness_gen_sidecar_path ?? request.witnessGenSidecarPath,
      'witness_gen_sidecar_path',
    ),
    random: request.random,
    hSignUserOp: requireString(
      request.h_sign_user_op ?? request.hSignUserOp,
      'h_sign_user_op',
    ),
    anchor: request.anchor,
    merkleRoot: requireString(
      request.merkle_root ?? request.merkleRoot,
      'merkle_root',
    ),
    credentials: request.credentials.map(toNativeCredential),
  };
}

function toProofResult(result: {
  proofs: string[][];
  sharedInputs: string[];
  partialRhsList: string[];
  jwtExpList: string[];
}): ProveResult {
  return {
    proofs: result.proofs,
    shared_inputs: result.sharedInputs,
    partial_rhs_list: result.partialRhsList,
    jwt_exp_list: result.jwtExpList,
  };
}

function makeRunId(): string {
  return `zkap-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2)}`;
}

type IosWitnessRunnerResult = {
  witnessBundlePath?: unknown;
  sha256?: unknown;
  byteLength?: unknown;
};

async function runIosWitness(
  prepared: ZkapPreparedWitnessInputs,
): Promise<ZkapWitnessBundleFile> {
  const inputJson = JSON.stringify({
    run_id: makeRunId(),
    chunk_size: IOS_WITNESS_CHUNK_SIZE,
    wasm_base64: prepared.wasmBase64,
    request_json_base64: prepared.requestJsonBase64,
    config_json_base64: prepared.configJsonBase64,
    witness_gen_sha256: prepared.witnessGenSha256,
    request_json_sha256: prepared.requestJsonSha256,
    config_json_sha256: prepared.configJsonSha256,
    wasm_byte_length: prepared.wasmByteLength.toString(),
    request_json_byte_length: prepared.requestJsonByteLength.toString(),
    config_json_byte_length: prepared.configJsonByteLength.toString(),
  });

  const resultJson = await NativeZkapReactNative.runWitnessInWkWebView(inputJson);
  const parsed = JSON.parse(resultJson) as IosWitnessRunnerResult;
  if (
    typeof parsed.witnessBundlePath !== 'string' ||
    typeof parsed.sha256 !== 'string' ||
    typeof parsed.byteLength !== 'number'
  ) {
    throw new Error('[zkap/sdk-react-native] invalid WKWebView witness result');
  }
  return {
    witnessBundlePath: parsed.witnessBundlePath,
    sha256: parsed.sha256,
    byteLength: BigInt(parsed.byteLength),
  };
}

// ──────────────────────────────────────────────────────────────────
// Supported API
// ──────────────────────────────────────────────────────────────────

/**
 * Compute a Poseidon hash of one or more field-element strings (hex or decimal).
 * Returns the result as a 0x-prefixed hex string.
 */
export async function generateHash(messages: string[]): Promise<string> {
  ensureInitialized();
  return withZkapErrorMessage(() => nativeGenerateHash(messages));
}

/**
 * Generate a Poseidon threshold anchor from JWT credential secrets.
 * Returns anchor polynomial evaluation points as hex strings.
 */
export async function generateAnchor(
  config: CircuitConfig,
  secrets: Secret[],
): Promise<{ evaluations: string[] }> {
  ensureInitialized();
  return withZkapErrorMessage(() => nativeGenerateAnchor(toNativeConfig(config), secrets));
}

/**
 * Derive the k-of-n anchor slot selector (0/1 per slot) from `k` known
 * secrets and the anchor evaluations (hex or decimal strings, e.g. from
 * on-chain `getAnchor()`). Membership check for shuffled anchors whose
 * dummy-slot preimages were discarded at registration — throws
 * "No valid selector found" when the secrets, in their slot-ascending
 * relative order, are not members of the anchor.
 */
export async function deriveSelector(
  config: CircuitConfig,
  secrets: Secret[],
  anchor_evaluations: string[],
): Promise<number[]> {
  ensureInitialized();
  return withZkapErrorMessage(() =>
    nativeDeriveSelector(toNativeConfig(config), secrets, anchor_evaluations)
  );
}

/**
 * Compute per-audience hashes and the combined audience-list hash.
 */
export async function generateAudHash(
  config: CircuitConfig,
  aud_list: string[],
): Promise<{ aud_hashes: string[]; h_aud_list: string }> {
  ensureInitialized();
  const result = withZkapErrorMessage(() =>
    nativeGenerateAudHash(toNativeConfig(config), aud_list)
  );
  return {
    aud_hashes: result.audHashes,
    h_aud_list: result.hAudList,
  };
}

/**
 * Compute the Merkle leaf hash for an issuer and RSA public-key modulus (base64-encoded).
 */
export async function generateLeafHash(
  config: CircuitConfig,
  iss: string,
  pk_b64: string,
): Promise<string> {
  ensureInitialized();
  return withZkapErrorMessage(() => nativeGenerateLeafHash(toNativeConfig(config), iss, pk_b64));
}

/**
 * Generate Groth16 proofs (on-device proving).
 *
 * Requires a manifest-validated CRS directory (manifest.json, circuit.ar1cs,
 * pk.bin, vk.bin, pvk.bin, config.json) PLUS the independently-distributed
 * witness generator supplied via `request.witnessGenPath` +
 * `request.witnessGenSidecarPath` (no longer bundled in the CRS directory).
 */
export async function prove(
  config: CircuitConfig,
  request: ProveRequest,
): Promise<ProveResult> {
  ensureInitialized();
  const nativeConfig = toNativeConfig(config);
  const nativeRequest = toNativeRequest(request);
  if (Platform.OS === 'ios') {
    const prepared = withZkapErrorMessage(() =>
      nativePrepareWitnessInputs(nativeConfig, nativeRequest)
    );
    const witness = await runIosWitness(prepared);
    return toProofResult(
      withZkapErrorMessage(() =>
        nativeProveFromWitnessBundleFile(nativeConfig, nativeRequest, witness)
      )
    );
  }

  return toProofResult(
    withZkapErrorMessage(() => nativeProve(nativeConfig, nativeRequest))
  );
}

// ──────────────────────────────────────────────────────────────────
// Unsupported API — explicit error messages
// ──────────────────────────────────────────────────────────────────

/**
 * NOT supported on React Native.
 * groth16Setup() has been removed from all SDK packages as of v0.1.2.
 */
export function groth16Setup(): never {
  throw new Error(
    '[zkap/sdk-react-native] groth16Setup() is not supported on mobile. ' +
    'Note: this function has been removed from all SDK packages as of v0.1.2.',
  );
}

/**
 * NOT supported on React Native.
 * Verification is currently kept on-chain / server-side for mobile consumers.
 */
export function verify(): never {
  throw new Error(
    '[zkap/sdk-react-native] verify() is not supported on mobile. ' +
    'Use the on-chain verifier or the Node SDK verify() helper.',
  );
}
