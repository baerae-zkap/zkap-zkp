#!/usr/bin/env node
/**
 * Regenerate golden/anchor-vectors.json from the locally built
 * @baerae/zkap-zkp-node binding (`npm run build` in packages/sdk-node first).
 *
 * The golden file locks three contracts across node and wasm (see
 * packages/sdk-node/__test__/anchor-golden.spec.ts and
 * packages/sdk-wasm/tests/anchor_golden.rs):
 *   1. anchor generation for the padToThree shapes (1/2/3 accounts placed in
 *      an explicit 6-slot layout with named dummies),
 *   2. deriveSelector membership results + error codes (NO_VALID_SELECTOR /
 *      DIMENSION_MISMATCH on the poisoning regression cases),
 *   3. audience-hash results per aud combination.
 *
 * Expected values are captured from the node binding at generation time; the
 * specs then re-run both runtimes against the committed file, so any quoting/
 * padding/search-order drift (the 0.1.5-class regression) fails loudly.
 */
import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const repoRoot = resolve(import.meta.dirname, '..')
const { generateAnchor, deriveSelector, generateAudHash, generateHash } = await import(
  resolve(repoRoot, 'packages/sdk-node/index.js')
)

// Production circuit configs (3-of-6 shuffled key-update shape + 1-of-1 deployment shape).
const BASE = {
  maxJwtB64Len: 960,
  maxPayloadB64Len: 832,
  maxAudLen: 155,
  maxExpLen: 20,
  maxIssLen: 93,
  maxNonceLen: 93,
  maxSubLen: 93,
  treeHeight: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbiddenString: 'forbidden',
}
const CONFIG_3OF6 = { ...BASE, n: 6, k: 3, numAudienceLimit: 6 }
const CONFIG_1OF1 = { ...BASE, n: 1, k: 1, numAudienceLimit: 1 }

// Raw identity triples — no quotes; the SDK quotes internally (0.1.5+ contract).
const A = { sub: '110169484474386276334', iss: 'https://accounts.google.com', aud: '407408718192.apps.googleusercontent.com' }
const B = { sub: '3405691582', iss: 'https://kauth.kakao.com', aud: 'kakao-client-example' }
const C = { sub: '001234.abcdef1234567890abcdef1234567890.1234', iss: 'https://appleid.apple.com', aud: 'app.zkap.web3.service' }
const X = { sub: '999999999999999999999', iss: 'https://accounts.google.com', aud: '407408718192.apps.googleusercontent.com' }
const EMPTY_APPLE = { sub: '', iss: '', aud: 'app.zkap.web3.service' }
const REAL_APPLE = C

const dummy = (i) => ({ sub: `dummy-sub-${i}`, iss: `https://dummy-${i}.invalid`, aud: `dummy-aud-${i}` })
const [D1, D2, D3] = [dummy(1), dummy(2), dummy(3)]

// Explicit 6-slot layouts fixing the (normally shuffled, discarded) dummy
// placement so the anchor is reproducible. padToThree shapes:
//   1 account  → [A,A,A], 2 accounts → [A,B,A], 3 accounts → [A,B,C].
const ANCHORS = {
  // [A,A,A] at slots 1,3,4
  'one-account': [D1, A, D2, A, A, D3],
  // [A,B,A] at slots 0,2,5
  'two-account': [A, D1, B, D2, D3, A],
  // [A,B,C] at slots 2,4,5
  'three-account': [D1, D2, A, D3, B, C],
  // Poisoned-anchor fixture: padToThree of [A, EMPTY_APPLE] → [A,E,A] at
  // slots 0,2,5. An anchor baked with an empty identity can never be matched
  // by the real account — no provider issues a JWT with an empty sub.
  'poisoned-empty-identity': [A, D1, EMPTY_APPLE, D2, D3, A],
}

const anchors = {}
for (const [name, secrets6] of Object.entries(ANCHORS)) {
  anchors[name] = { secrets6, evaluations: generateAnchor(CONFIG_3OF6, secrets6).evaluations }
}

const quoted = (s) => ({ sub: `"${s.sub}"`, iss: `"${s.iss}"`, aud: `"${s.aud}"` })

const DERIVE_CASES = [
  { name: 'one-account [A,A,A]', anchor: 'one-account', secrets: [A, A, A] },
  { name: 'two-account [A,B,A]', anchor: 'two-account', secrets: [A, B, A] },
  { name: 'three-account [A,B,C]', anchor: 'three-account', secrets: [A, B, C] },
  { name: 'poisoned anchor accepts the empty identity it was built with', anchor: 'poisoned-empty-identity', secrets: [A, EMPTY_APPLE, A] },
  { name: 'order swapped [B,A,C]', anchor: 'three-account', secrets: [B, A, C] },
  { name: 'double-quoted secrets (0.1.5 contract violation)', anchor: 'three-account', secrets: [quoted(A), quoted(B), quoted(C)] },
  { name: 'empty identity vs healthy anchor', anchor: 'three-account', secrets: [{ sub: '', iss: '', aud: A.aud }, B, C] },
  { name: 'different account [A,B,X]', anchor: 'three-account', secrets: [A, B, X] },
  { name: 'real account vs poisoned (empty-identity) anchor', anchor: 'poisoned-empty-identity', secrets: [A, REAL_APPLE, A] },
  { name: 'secrets count != k', anchor: 'three-account', secrets: [A, B] },
  { name: 'anchor evaluations != n-k+1', anchor: 'three-account', anchorSlice: 3, secrets: [A, B, C] },
]

const deriveCases = DERIVE_CASES.map((c) => {
  const evals = anchors[c.anchor].evaluations
  const anchorEvaluations = c.anchorSlice ? evals.slice(0, c.anchorSlice) : evals
  let expect
  try {
    expect = { selector: deriveSelector(CONFIG_3OF6, c.secrets, anchorEvaluations) }
  } catch (e) {
    expect = { errorCode: e.code, messageIncludes: e.message.includes('No valid selector found') ? 'No valid selector found' : 'Dimension mismatch' }
  }
  return { name: c.name, anchor: c.anchor, ...(c.anchorSlice ? { anchorSlice: c.anchorSlice } : {}), secrets: c.secrets, expect }
})

const AUD_CASES = [
  { config: '1of1', audiences: [A.aud] },
  { config: '3of6', audiences: [A.aud, A.aud, A.aud, A.aud, A.aud, A.aud] },
  { config: '3of6', audiences: [A.aud, B.aud, C.aud, A.aud, B.aud, C.aud] },
  { config: '3of6', audiences: [D1.aud, D2.aud, A.aud, D3.aud, B.aud, C.aud] },
]
const audHashCases = AUD_CASES.map((c) => ({
  ...c,
  expect: generateAudHash(c.config === '1of1' ? CONFIG_1OF1 : CONFIG_3OF6, c.audiences),
}))

const hashCases = [
  { messages: ['0x01', '0x02'], expect: { hash: generateHash(['0x01', '0x02']) } },
  (() => {
    try {
      generateHash(['not-a-field-element'])
      throw new Error('expected generateHash to reject')
    } catch (e) {
      return { messages: ['not-a-field-element'], expect: { errorCode: e.code } }
    }
  })(),
]

const golden = {
  $comment: 'Generated by scripts/generate-anchor-golden.mjs — do not hand-edit. Locks node/wasm anchor+deriveSelector+audHash parity and error codes.',
  config3of6: CONFIG_3OF6,
  config1of1: CONFIG_1OF1,
  anchors,
  deriveCases,
  audHashCases,
  hashCases,
}

const out = resolve(repoRoot, 'golden/anchor-vectors.json')
writeFileSync(out, JSON.stringify(golden, null, 2) + '\n')
console.log(`wrote ${out}`)
console.log(`anchors: ${Object.keys(anchors).length}, deriveCases: ${deriveCases.length}, audHashCases: ${audHashCases.length}`)
for (const c of deriveCases) {
  console.log(`  ${c.expect.selector ? `[${c.expect.selector.join(',')}]` : c.expect.errorCode}  ${c.name}`)
}
