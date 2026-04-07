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
  anchor: string[];
  h_sign_user_op: string;
  random: string;
  aud_list: string[];
}

export interface ProveResult {
  proofs: string[];
  public_inputs: string[][];
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
 * Requires PK to be downloaded and cached via initProveArtifacts().
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
 * groth16Setup() requires a server environment with large CRS data.
 * Use @baerae/zkap-zkp (Node.js) for setup.
 */
export function groth16Setup(): never {
  throw new Error(
    '[zkap/sdk-react-native] groth16Setup() is not supported on mobile. ' +
    'Use @baerae/zkap-zkp (Node.js) for server-side trusted setup.'
  );
}

/**
 * NOT supported on React Native.
 * verify() uses a verifying key hardcoded in a smart contract.
 * Use @baerae/zkap-zkp (Node.js) for server-side verification.
 */
export function verify(): never {
  throw new Error(
    '[zkap/sdk-react-native] verify() is not supported on mobile. ' +
    'Use @baerae/zkap-zkp (Node.js) for server-side verification.'
  );
}

export { initProveArtifacts } from './artifact-manager';
