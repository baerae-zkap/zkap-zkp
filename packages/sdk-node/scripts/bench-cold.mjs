#!/usr/bin/env node
/**
 * Cold-start benchmark driver for the release witness wasm synthesize path.
 *
 * Spawns `bench-prove.mjs` once per (backend × repetition) in a brand
 * new node child process so every measurement sees a cold napi addon
 * load, a cold pk.bin mmap, and a cold wasmtime instance. No process
 * is reused.
 *
 * Args:
 *   --wasm <path>     fixture JSON for the release witness wasm bundle
 *   --reps <n>        repetitions per backend (default 1; first run
 *                     is the canonical cold number — extras are
 *                     informational since each child is fresh).
 *
 * Output: a small markdown report to stdout.
 */

import { spawn } from 'node:child_process'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const SELF_DIR = dirname(fileURLToPath(import.meta.url))
const BENCH_SCRIPT = resolve(SELF_DIR, 'bench-prove.mjs')

function parseArgs(argv) {
  const out = { reps: 1 }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--wasm') out.wasm = argv[++i]
    else if (a === '--reps') out.reps = Number(argv[++i])
  }
  return out
}

function runOnce(fixturePath) {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [BENCH_SCRIPT, fixturePath], {
      stdio: ['ignore', 'pipe', 'inherit'],
    })
    let stdout = ''
    child.stdout.on('data', (b) => (stdout += b.toString()))
    child.on('exit', (code) => {
      if (code !== 0) return rej(new Error(`child exited ${code}`))
      try {
        res(JSON.parse(stdout.trim().split('\n').pop()))
      } catch (e) {
        rej(new Error(`parse child stdout failed: ${e.message}\n--- raw ---\n${stdout}`))
      }
    })
  })
}

const { wasm, reps } = parseArgs(process.argv.slice(2))
if (!wasm) {
  console.error('usage: bench-cold.mjs --wasm <fixture.json> [--reps N]')
  process.exit(2)
}

const groups = []
if (wasm) groups.push({ label: 'wasm synthesize (wasmtime)', fixturePath: wasm })

const allResults = []
for (const g of groups) {
  const runs = []
  for (let i = 0; i < reps; i++) {
    process.stderr.write(`[cold-bench] ${g.label} run ${i + 1}/${reps} …\n`)
    const r = await runOnce(g.fixturePath)
    runs.push(r)
  }
  allResults.push({ ...g, runs })
}

// Markdown report.
const fmt = (n) => (typeof n === 'number' ? n.toLocaleString('en-US', { maximumFractionDigits: 2 }) : String(n))

console.log(`# zkap-zkp-node • cold prove() benchmark`)
console.log(``)
console.log(`Each row is one fresh-child-process measurement (no warmup). All times in ms, memory in MB (RSS).`)
console.log(``)
console.log(`| backend | run | synthesizeMs | proveMs | totalMs | memBefore | memAfter | memDelta | memPeak | k |`)
console.log(`|---|---|---:|---:|---:|---:|---:|---:|---:|---:|`)
for (const g of allResults) {
  for (let i = 0; i < g.runs.length; i++) {
    const r = g.runs[i]
    console.log(
      `| ${r.backend} | ${i + 1} | ${fmt(r.synthesizeMs)} | ${fmt(r.proveMs)} | ${fmt(r.totalMs)} | ${fmt(r.memBeforeMb)} | ${fmt(r.memAfterMb)} | ${fmt(r.memDeltaMb)} | ${fmt(r.memPeakMb)} | ${r.k} |`,
    )
  }
}
