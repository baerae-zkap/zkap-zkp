#!/usr/bin/env node
/**
 * Cold benchmark: one prove() call per fresh node process.
 *
 * Usage:
 *   node scripts/bench-prove.mjs <fixture-path>
 *
 * Designed to be invoked from `bench-cold.mjs`, which spawns this
 * script with `--no-warmup` semantics by virtue of being a brand-new
 * child process per measurement.
 *
 * Output: a single line of JSON to stdout, with shape:
 *   {
 *     "backend": "wasm",
 *     "synthesizeMs": number,
 *     "proveMs": number,
 *     "totalMs": number,
 *     "memBeforeMb": number,   // RSS in MB before prove()
 *     "memAfterMb": number,    // RSS in MB after prove()
 *     "memDeltaMb": number,    // memAfterMb - memBeforeMb
 *     "memPeakMb": number,     // max(rss) across before/after samples
 *     "k": number              // proofs.length
 *   }
 *
 * Human-readable progress lines go to stderr so stdout stays
 * machine-parseable.
 */

import { readFileSync, existsSync } from 'node:fs'
import { performance } from 'node:perf_hooks'

const fixturePath = process.argv[2]
if (!fixturePath || !existsSync(fixturePath)) {
  console.error(`usage: bench-prove.mjs <fixture-path>; got ${fixturePath}`)
  process.exit(2)
}

function rssMb() {
  return process.memoryUsage().rss / (1024 * 1024)
}

const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
const memBeforeImport = rssMb()
console.error(`[bench] memBeforeImport = ${memBeforeImport.toFixed(1)} MB`)

// Cold import — pulls in the napi addon for the first time in this process.
const bindings = await import('../index.js')

const memBeforeProve = rssMb()
console.error(`[bench] memBeforeProve  = ${memBeforeProve.toFixed(1)} MB`)

const wallStart = performance.now()
const out = bindings.prove(fixture.config, { ...fixture.request, manifestDir: fixture.manifestDir })
const wallEnd = performance.now()

const memAfterProve = rssMb()
console.error(`[bench] memAfterProve   = ${memAfterProve.toFixed(1)} MB`)

const result = {
  backend: out.timing.backend,
  synthesizeMs: Number(out.timing.synthesizeMs.toFixed(2)),
  proveMs: Number(out.timing.proveMs.toFixed(2)),
  totalMs: Number((wallEnd - wallStart).toFixed(2)),
  memBeforeImportMb: Number(memBeforeImport.toFixed(1)),
  memBeforeMb: Number(memBeforeProve.toFixed(1)),
  memAfterMb: Number(memAfterProve.toFixed(1)),
  memDeltaMb: Number((memAfterProve - memBeforeProve).toFixed(1)),
  memPeakMb: Number(Math.max(memBeforeImport, memBeforeProve, memAfterProve).toFixed(1)),
  k: out.proofs.length,
}
process.stdout.write(JSON.stringify(result) + '\n')
