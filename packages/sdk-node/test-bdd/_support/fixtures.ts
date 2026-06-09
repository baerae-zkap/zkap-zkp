/**
 * Shared fixtures for the mocha BDD suite. Kept structurally identical
 * to `__test__/hash.spec.ts` and `__test__/proof.spec.ts` so both
 * suites assert the same canonical shapes.
 */

import { existsSync, readFileSync } from 'node:fs'

export const HEX_RE = /^0x[0-9a-f]{64}$/i

/** n=6, k=3 config matching `zkap-circuit/tests/groth16_integration.rs`. */
export const DEFAULT_CONFIG = {
  maxJwtB64Len: 1024,
  maxPayloadB64Len: 640,
  maxAudLen: 155,
  maxExpLen: 20,
  maxIssLen: 93,
  maxNonceLen: 93,
  maxSubLen: 93,
  n: 6,
  k: 3,
  treeHeight: 4,
  numAudienceLimit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbiddenString: 'forbidden',
}

export const DEFAULT_SECRET = {
  sub: 'user-1234',
  iss: 'https://accounts.example.com',
  aud: 'my-client-id',
}

export const DEFAULT_SECRETS = Array.from({ length: 6 }, (_, i) => ({
  sub: `user-${i}`,
  iss: DEFAULT_SECRET.iss,
  aud: DEFAULT_SECRET.aud,
}))

/** 256-byte RSA modulus (all 0xAA), base64-encoded. */
export const PLACEHOLDER_RSA_MODULUS_B64 = Buffer.alloc(256, 0xaa).toString('base64')

/** Placeholder JWT — length-valid, content-invalid. */
export function placeholderJwt(): string {
  const header = Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url')
  const payload = Buffer.from('{"aud":"a","iss":"i","sub":"s","exp":1700000000}').toString(
    'base64url',
  )
  const sig = Buffer.alloc(256, 0xaa).toString('base64url')
  return `${header}.${payload}.${sig}`
}

const ZERO_FE = '0x00'

type CircuitParams = typeof DEFAULT_CONFIG

/** Placeholder prove request — shape-valid, witness-invalid. */
export function placeholderRequest(cfg: CircuitParams, manifestDir: string) {
  const k = cfg.k
  const anchorLen = cfg.n - cfg.k + 1
  const th = cfg.treeHeight
  return {
    manifestDir,
    random: ZERO_FE,
    hSignUserOp: ZERO_FE,
    anchor: Array.from({ length: anchorLen }, () => ZERO_FE),
    merkleRoot: ZERO_FE,
    credentials: Array.from({ length: k }, () => ({
      jwt: placeholderJwt(),
      rsaModulusB64: PLACEHOLDER_RSA_MODULUS_B64,
      merklePath: Array.from({ length: th }, () => ZERO_FE),
      merkleLeafIdx: 0,
    })),
  }
}

/** Loads a `proof_fixture.json` produced by zkap-service's
 * `gen_proof_fixture` integration test. */
export type ProofFixture = {
  manifestDir: string
  /** App-supplied path to `witness_gen.wasm` (decoupled from the CRS bundle). */
  witnessGenPath: string
  /** App-supplied path to the `witness_gen.json` sidecar. */
  witnessGenSidecarPath: string
  config: CircuitParams
  request: Omit<ReturnType<typeof placeholderRequest>, 'manifestDir'>
}

export function loadFixture(envVar: string): ProofFixture | null {
  const path = process.env[envVar]
  if (!path || !existsSync(path)) return null
  return JSON.parse(readFileSync(path, 'utf8')) as ProofFixture
}
