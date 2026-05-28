/**
 * Tests for hash-related NAPI bindings in @baerae/zkap-zkp-node.
 *
 * Run after building the native binary:
 *   npm run build  (or cargo-napi build --platform)
 *   npm test
 *
 * All four hash functions under test:
 *   - generateHash(messages)
 *   - generateAnchor(config, secrets)
 *   - generateAudHash(config, audList)
 *   - generateLeafHash(config, iss, pkB64)
 */

import test from 'ava'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

// ---------------------------------------------------------------------------
// Guard: skip all tests if the native binary has not been built yet.
// ---------------------------------------------------------------------------
const PACKAGE_ROOT = resolve(import.meta.dirname ?? __dirname, '..')
const INDEX_JS = resolve(PACKAGE_ROOT, 'index.js')

const binaryMissing = !existsSync(INDEX_JS)
if (binaryMissing) {
  console.warn(
    '[hash.spec.ts] Native binary not found. Run `npm run build` first. All tests skipped.',
  )
}

// Dynamic import so the module-load error is deferred past the guard above.
const bindings = binaryMissing ? null : await import(INDEX_JS)
const generateHash = bindings?.generateHash
const generateAnchor = bindings?.generateAnchor
const generateAudHash = bindings?.generateAudHash
const generateLeafHash = bindings?.generateLeafHash

// Use test.skip for all cases when the binary is not built yet.
const it = binaryMissing ? test.skip : test

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

// Values match the integration test fixture in zkap-circuit/tests/groth16_integration.rs.
// Lengths (max_iss_len, max_sub_len, etc.) must be multiples of 31 bytes
// (BN254 scalar field limb width: (254-1)/8 = 31).
const DEFAULT_CONFIG = {
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

/** A single well-formed JWT credential triple. */
const DEFAULT_SECRET = {
  sub: 'user-1234',
  iss: 'https://accounts.example.com',
  aud: 'my-client-id',
}

// generateAnchor requires exactly n=6 secrets (Vandermonde matrix dimension).
const DEFAULT_SECRETS = Array.from({ length: 6 }, (_, i) => ({
  sub: `user-${i}`,
  iss: DEFAULT_SECRET.iss,
  aud: DEFAULT_SECRET.aud,
}))

// Regex for a 0x-prefixed 64-char (32-byte / 256-bit) hex string.
const HEX_RE = /^0x[0-9a-f]{64}$/i

// ---------------------------------------------------------------------------
// generateHash
// ---------------------------------------------------------------------------

it('generateHash: returns 0x-prefixed 256-bit hex string for a single message', async (t) => {
  const result: string = await generateHash(['12345'])
  t.regex(result, HEX_RE, `Expected hex256, got: ${result}`)
})

it('generateHash: returns same value for identical inputs (deterministic)', async (t) => {
  const a: string = await generateHash(['42', '99'])
  const b: string = await generateHash(['42', '99'])
  t.is(a, b)
})

it('generateHash: different messages produce different hashes', async (t) => {
  const a: string = await generateHash(['1'])
  const b: string = await generateHash(['2'])
  t.not(a, b)
})

it('generateHash: accepts hex-prefixed input strings (chained hashing)', async (t) => {
  const first: string = await generateHash(['1'])
  const result: string = await generateHash([first])
  t.regex(result, HEX_RE)
})

it('generateHash: rejects non-numeric / non-hex string (throws synchronously)', (t) => {
  t.throws(() => generateHash(['not-a-field-element']), { instanceOf: Error })
})

// ---------------------------------------------------------------------------
// generateAnchor
// ---------------------------------------------------------------------------

it('generateAnchor: returns JsAnchorResult with non-empty evaluations array', async (t) => {
  const result = await generateAnchor(DEFAULT_CONFIG, DEFAULT_SECRETS)
  t.truthy(result, 'result should be defined')
  t.true(Array.isArray(result.evaluations), 'evaluations should be an array')
  t.true(result.evaluations.length > 0, 'evaluations should not be empty')
})

it('generateAnchor: every evaluation is a 0x-prefixed 256-bit hex string', async (t) => {
  const result = await generateAnchor(DEFAULT_CONFIG, DEFAULT_SECRETS)
  for (const ev of result.evaluations) {
    t.regex(ev as string, HEX_RE, `Unexpected evaluation format: ${ev}`)
  }
})

it('generateAnchor: different secrets produce different evaluations', async (t) => {
  const secretsA = DEFAULT_SECRETS
  const secretsB = DEFAULT_SECRETS.map((s, i) => ({ ...s, sub: `alt-user-${i}` }))
  const a = await generateAnchor(DEFAULT_CONFIG, secretsA)
  const b = await generateAnchor(DEFAULT_CONFIG, secretsB)
  t.notDeepEqual(a.evaluations, b.evaluations)
})

it('generateAnchor: rejects wrong number of secrets (throws synchronously)', (t) => {
  // n=6 required; passing 1 should throw a dimension mismatch error.
  t.throws(() => generateAnchor(DEFAULT_CONFIG, [DEFAULT_SECRET]), { instanceOf: Error })
})

it('generateAnchor: rejects empty secrets array (throws synchronously)', (t) => {
  t.throws(() => generateAnchor(DEFAULT_CONFIG, []), { instanceOf: Error })
})

it('generateAnchor: rejects null config (throws synchronously)', (t) => {
  t.throws(() => generateAnchor(null, DEFAULT_SECRETS), { instanceOf: Error })
})

it('generateAnchor: rejects null secrets (throws synchronously)', (t) => {
  t.throws(() => generateAnchor(DEFAULT_CONFIG, null), { instanceOf: Error })
})

// ---------------------------------------------------------------------------
// generateAudHash
// ---------------------------------------------------------------------------

it('generateAudHash: returns JsAudHashResult with audHashes and hAudList', async (t) => {
  const result = await generateAudHash(DEFAULT_CONFIG, ['my-client-id'])
  t.truthy(result)
  t.true(Array.isArray(result.audHashes), 'audHashes should be an array')
  t.regex(result.hAudList as string, HEX_RE, 'hAudList should be hex256')
})

it('generateAudHash: every per-audience hash is hex256', async (t) => {
  const result = await generateAudHash(DEFAULT_CONFIG, ['aud-1', 'aud-2'])
  for (const h of result.audHashes) {
    t.regex(h as string, HEX_RE, `Unexpected aud hash format: ${h}`)
  }
})

it('generateAudHash: audHashes length equals numAudienceLimit (padded)', async (t) => {
  const result = await generateAudHash(DEFAULT_CONFIG, ['aud-1'])
  t.is(
    result.audHashes.length,
    DEFAULT_CONFIG.numAudienceLimit,
    'padded audHashes length should equal numAudienceLimit',
  )
})

it('generateAudHash: different audience lists produce different hAudList', async (t) => {
  const a = await generateAudHash(DEFAULT_CONFIG, ['client-a'])
  const b = await generateAudHash(DEFAULT_CONFIG, ['client-b'])
  t.not(a.hAudList, b.hAudList)
})

it('generateAudHash: rejects null config (throws synchronously)', (t) => {
  t.throws(() => generateAudHash(null, ['aud']), { instanceOf: Error })
})

// ---------------------------------------------------------------------------
// generateLeafHash
// ---------------------------------------------------------------------------

/**
 * Minimal RSA public key modulus encoded in base64.
 * 256 bytes = 2048-bit modulus, all 0xFF — valid size, arbitrary content.
 */
const DUMMY_PK_B64 = Buffer.alloc(256, 0xff).toString('base64')

it('generateLeafHash: returns 0x-prefixed 256-bit hex string', async (t) => {
  const result: string = await generateLeafHash(
    DEFAULT_CONFIG,
    DEFAULT_SECRET.iss,
    DUMMY_PK_B64,
  )
  t.regex(result, HEX_RE, `Expected hex256, got: ${result}`)
})

it('generateLeafHash: is deterministic for the same inputs', async (t) => {
  const a = await generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, DUMMY_PK_B64)
  const b = await generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, DUMMY_PK_B64)
  t.is(a, b)
})

it('generateLeafHash: different issuers produce different leaf hashes', async (t) => {
  const a = await generateLeafHash(DEFAULT_CONFIG, 'https://issuer-a.example.com', DUMMY_PK_B64)
  const b = await generateLeafHash(DEFAULT_CONFIG, 'https://issuer-b.example.com', DUMMY_PK_B64)
  t.not(a, b)
})

it('generateLeafHash: different public keys produce different leaf hashes', async (t) => {
  const pkA = Buffer.alloc(256, 0xaa).toString('base64')
  const pkB = Buffer.alloc(256, 0xbb).toString('base64')
  const a = await generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, pkA)
  const b = await generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, pkB)
  t.not(a, b)
})

it('generateLeafHash: rejects null config (throws synchronously)', (t) => {
  t.throws(() => generateLeafHash(null, DEFAULT_SECRET.iss, DUMMY_PK_B64), { instanceOf: Error })
})

it('generateLeafHash: rejects invalid base64 for public key (throws synchronously)', (t) => {
  t.throws(
    () => generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, '!!!not-base64!!!'),
    { instanceOf: Error },
  )
})
