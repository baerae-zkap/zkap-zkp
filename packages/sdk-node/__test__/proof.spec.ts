/**
 * Integration tests for proof functions: prove → verify.
 *
 * Requires pre-generated fixtures:
 *   __test__/fixtures/pk.bin          — proving key binary
 *   __test__/fixtures/proof_input.json — proof input data (see JsProofRequest for field names)
 *
 * Run only when fixtures are available:
 *   npm run build && npm test
 */

import test from 'ava'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// Skip manifest.json CRS integrity check in tests — pk is pre-generated
// and no generate_crs manifest exists in the fixture directory.
process.env['ZKAP_SKIP_MANIFEST_CHECK'] = '1'

// ---------------------------------------------------------------------------
// Guards: skip if binary or fixtures not built/provided
// ---------------------------------------------------------------------------
const PACKAGE_ROOT = resolve(import.meta.dirname ?? __dirname, '..')
const INDEX_JS = resolve(PACKAGE_ROOT, 'index.js')
const PK_PATH = resolve(PACKAGE_ROOT, '__test__/fixtures/pk.bin')
const PROOF_INPUT_PATH = resolve(PACKAGE_ROOT, '__test__/fixtures/proof_input.json')

const binaryMissing = !existsSync(INDEX_JS)
if (binaryMissing) {
  console.warn('[proof.spec.ts] Native binary not found. Skipping all tests.')
}

const fixturesMissing = !existsSync(PK_PATH) || !existsSync(PROOF_INPUT_PATH)
if (fixturesMissing) {
  console.warn('[proof.spec.ts] Fixtures not found (pk.bin or proof_input.json). Skipping all tests.')
}

const bindings = binaryMissing ? null : await import(INDEX_JS)
const prove = bindings?.prove

const it = (binaryMissing || fixturesMissing) ? test.skip : test

// ---------------------------------------------------------------------------
// Load fixture data
// ---------------------------------------------------------------------------
const fixture = fixturesMissing
  ? null
  : JSON.parse(readFileSync(PROOF_INPUT_PATH, 'utf8'))

const CONFIG = fixturesMissing ? null : {
  maxJwtB64Len: fixture.max_jwt_b64_len,
  maxPayloadB64Len: fixture.max_payload_b64_len,
  maxAudLen: fixture.max_aud_len,
  maxExpLen: fixture.max_exp_len,
  maxIssLen: fixture.max_iss_len,
  maxNonceLen: fixture.max_nonce_len,
  maxSubLen: fixture.max_sub_len,
  n: fixture.n,
  k: fixture.k,
  treeHeight: fixture.tree_height,
  numAudienceLimit: fixture.num_audience_limit,
  claims: fixture.claims,
  forbiddenString: fixture.forbidden_string,
}

const REQUEST = fixturesMissing ? null : {
  pkPath: PK_PATH,
  jwts: fixture.jwts,
  pkOps: fixture.pk_ops,
  merklePaths: fixture.merkle_paths,
  leafIndices: fixture.leaf_indices,
  root: fixture.root,
  anchorEvals: fixture.anchor_evals,
  hanchor: fixture.hanchor,
  hSignUserOp: fixture.h_sign_user_op,
  random: fixture.random,
  audHashList: fixture.aud_hash_list,
}

// ---------------------------------------------------------------------------
// prove + verify (end-to-end)
// ---------------------------------------------------------------------------

it('prove: generates valid proof from fixture input', async (t) => {
  t.timeout(600_000) // 10 min

  const proofOutput = await prove(CONFIG, REQUEST)

  t.true(Array.isArray(proofOutput.proofs), 'proofs should be an array')
  t.true(proofOutput.proofs.length > 0, 'should produce at least one proof')
  t.is(proofOutput.proofs[0].length, 8, 'each proof should have 8 Solidity strings')
  t.true(Array.isArray(proofOutput.sharedInputs), 'sharedInputs should be an array')
  t.is(proofOutput.sharedInputs.length, 6, 'sharedInputs should have 6 elements')
  t.is(proofOutput.partialRhsList.length, proofOutput.proofs.length, 'partialRhsList length matches proofs')
  t.is(proofOutput.jwtExpList.length, proofOutput.proofs.length, 'jwtExpList length matches proofs')
})

