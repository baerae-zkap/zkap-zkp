import { requireNativeModule } from 'expo-modules-core';

const ZkapSdk = requireNativeModule('ZkapSdk');

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

export interface ProveRequest {
  pk_path: string;
  jwts: string[];
  pk_ops: string[];
  merkle_paths: string[][];
  leaf_indices: number[];
  root: string;
  /** Anchor polynomial evaluations (N - K + 1 entries). */
  anchor_evals: string[];
  /** Anchor chain hash (hanchor). */
  hanchor: string;
  h_sign_user_op: string;
  random: string;
  /** Pre-computed audience hashes (from generateAudHash). */
  aud_hash_list: string[];
}

export interface ProveResult {
  /** Solidity-compatible proof per proof: [ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy] */
  proofs: string[][];
  /** Public inputs shared across all JWTs (indices 0,1,2,3,6,7) as decimal strings */
  shared_inputs: string[];
  /** partial_rhs per JWT (index 5) as decimal string */
  partial_rhs_list: string[];
  /** jwt_exp per JWT (index 4) as decimal string */
  jwt_exp_list: string[];
}

// ──────────────────────────────────────────────────────────────────
// Supported API
// ──────────────────────────────────────────────────────────────────

/**
 * Compute a Poseidon hash of one or more field-element strings (hex or decimal).
 * Returns the result as a 0x-prefixed hex string.
 */
export async function generateHash(messages: string[]): Promise<string> {
  const result: string = await ZkapSdk.generateHash(
    JSON.stringify({ messages })
  );
  return JSON.parse(result).result as string;
}

/**
 * Generate a Poseidon threshold anchor from JWT credential secrets.
 * Returns anchor polynomial evaluation points as hex strings.
 */
export async function generateAnchor(
  config: CircuitConfig,
  secrets: Secret[]
): Promise<{ evaluations: string[] }> {
  const result: string = await ZkapSdk.generateAnchor(
    JSON.stringify({ config, secrets })
  );
  return JSON.parse(result) as { evaluations: string[] };
}

/**
 * Compute per-audience hashes and the combined audience-list hash.
 */
export async function generateAudHash(
  config: CircuitConfig,
  aud_list: string[]
): Promise<{ aud_hashes: string[]; h_aud_list: string }> {
  const result: string = await ZkapSdk.generateAudHash(
    JSON.stringify({ config, aud_list })
  );
  return JSON.parse(result) as { aud_hashes: string[]; h_aud_list: string };
}

/**
 * Compute the Merkle leaf hash for an issuer and RSA public-key modulus (base64-encoded).
 */
export async function generateLeafHash(
  config: CircuitConfig,
  iss: string,
  pk_b64: string
): Promise<string> {
  const result: string = await ZkapSdk.generateLeafHash(
    JSON.stringify({ config, iss, pk_b64 })
  );
  return JSON.parse(result).result as string;
}

/**
 * Generate Groth16 proofs (on-device proving).
 * Requires a proving key file on disk.
 */
export async function prove(
  config: CircuitConfig,
  request: ProveRequest
): Promise<ProveResult> {
  const result: string = await ZkapSdk.prove(
    JSON.stringify({ config, request })
  );
  return JSON.parse(result) as ProveResult;
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
    'Note: this function has been removed from all SDK packages as of v0.1.2.'
  );
}

/**
 * NOT supported on React Native.
 * verify() has been removed from all SDK packages as of v0.1.2.
 */
export function verify(): never {
  throw new Error(
    '[zkap/sdk-react-native] verify() is not supported on mobile. ' +
    'Note: this function has been removed from all SDK packages as of v0.1.2.'
  );
}

