/**
 * Golden regression tests for anchor generation, deriveSelector membership,
 * and audience hashing, shared with the wasm runtime.
 *
 * Vectors live in golden/anchor-vectors.json (regenerate with
 * `node scripts/generate-anchor-golden.mjs` after an intentional contract
 * change). packages/sdk-wasm/tests/anchor_golden.rs runs the SAME file, so
 * any node/wasm divergence — quoting, padding, selector search order, error
 * codes (the 0.1.5-class contract drift) — fails one of the two suites.
 */

import test from 'ava'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const PACKAGE_ROOT = resolve(import.meta.dirname ?? __dirname, '..')
const INDEX_JS = resolve(PACKAGE_ROOT, 'index.js')

const binaryMissing = !existsSync(INDEX_JS)
if (binaryMissing) {
  console.warn(
    '[anchor-golden.spec.ts] Native binary not found. Run `npm run build` first. All tests skipped.',
  )
}

const bindings = binaryMissing ? null : await import(INDEX_JS)
const generateAnchor = bindings?.generateAnchor
const deriveSelector = bindings?.deriveSelector
const generateAudHash = bindings?.generateAudHash
const generateHash = bindings?.generateHash

const it = binaryMissing ? test.skip : test

const golden = JSON.parse(
  readFileSync(resolve(PACKAGE_ROOT, '../../golden/anchor-vectors.json'), 'utf8'),
)

for (const [name, anchor] of Object.entries(golden.anchors)) {
  it(`anchor '${name}' evaluations are stable`, (t) => {
    const result = generateAnchor(golden.config3of6, anchor.secrets6)
    t.deepEqual(result.evaluations, anchor.evaluations)
  })
}

for (const c of golden.deriveCases) {
  it(`deriveSelector: ${c.name}`, (t) => {
    const evals = golden.anchors[c.anchor].evaluations
    const anchorEvaluations = c.anchorSlice ? evals.slice(0, c.anchorSlice) : evals
    if (c.expect.selector) {
      t.deepEqual(deriveSelector(golden.config3of6, c.secrets, anchorEvaluations), c.expect.selector)
    } else {
      const err = t.throws(() => deriveSelector(golden.config3of6, c.secrets, anchorEvaluations))
      t.is(err.code, c.expect.errorCode)
      t.true(
        err.message.includes(c.expect.messageIncludes),
        `message ${JSON.stringify(err.message)} should include ${JSON.stringify(c.expect.messageIncludes)}`,
      )
    }
  })
}

golden.audHashCases.forEach((c, i) => {
  it(`audHash case ${i} (${c.config}, ${c.audiences.length} audiences)`, (t) => {
    const config = c.config === '1of1' ? golden.config1of1 : golden.config3of6
    const result = generateAudHash(config, c.audiences)
    t.deepEqual(result.audHashes, c.expect.audHashes)
    t.is(result.hAudList, c.expect.hAudList)
  })
})

golden.hashCases.forEach((c, i) => {
  it(`hash case ${i}`, (t) => {
    if (c.expect.hash) {
      t.is(generateHash(c.messages), c.expect.hash)
    } else {
      const err = t.throws(() => generateHash(c.messages))
      t.is(err.code, c.expect.errorCode)
    }
  })
})
