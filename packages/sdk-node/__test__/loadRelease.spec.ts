/**
 * NAPI-level tests for the `loadRelease(opts)` surface.
 *
 * `loadRelease` ingests zkap-circuit's flat prefixed release bundle
 * (e.g. `1-of-1-pk.bin`, `1-of-1-manifest.json`, …) and produces a
 * SHA-verified unprefixed staged directory under `os.tmpdir()` that
 * is compatible with `prove(config, { manifestDir, … })`.
 *
 * AC5 scenarios (a)-(i):
 *   (a) 1-of-1 success: 8-file staged set + manifestJson parse + releaseSha shape
 *   (b) 3-of-3 success: same shape assertions
 *   (c) missing releaseDir: throws with `loadRelease:` prefix
 *   (d) missing prefix file: deletes `1-of-1-pk.bin`, expects MissingArtifact
 *   (e) SHA mismatch: mutates one byte, expects IntegrityFailure with expected/got
 *   (f) malformed manifest: writes invalid JSON, expects MalformedManifest|parse
 *   (g) unknown shape: '2-of-2' → UnknownShape
 *   (h) idempotent: two sequential calls; warm-cache call < 2000ms
 *   (i) concurrent: 4 parallel calls return same stagedDir; final dir uncorrupted
 *
 * Run after building the native binary:
 *   npm run build && npm test
 */

import test from 'ava'
import { execSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------
const PACKAGE_ROOT = resolve(import.meta.dirname ?? __dirname, '..')
const INDEX_JS = resolve(PACKAGE_ROOT, 'index.js')

const binaryMissing = !existsSync(INDEX_JS)
if (binaryMissing) {
  console.warn(
    '[loadRelease.spec.ts] Native binary not found. Run `npm run build`. Tests skipped.',
  )
}

const bindings = binaryMissing ? null : await import(INDEX_JS)
const loadRelease = bindings?.loadRelease

// ---------------------------------------------------------------------------
// Locate the release directory
// ---------------------------------------------------------------------------
const DEFAULT_RELEASE_DIR = '/Users/leejw/01_baerae/zkap-circuit/dist/local-release/release'
const RELEASE_DIR = process.env['ZKAP_RELEASE_DIR'] ?? DEFAULT_RELEASE_DIR

const releaseDirMissing =
  !existsSync(join(RELEASE_DIR, '1-of-1-manifest.json')) ||
  !existsSync(join(RELEASE_DIR, '1-of-1-pk.bin')) ||
  !existsSync(join(RELEASE_DIR, '1-of-1-SHA256SUMS'))

if (releaseDirMissing && !binaryMissing) {
  console.warn(
    `[loadRelease.spec.ts] Release bundle not found at ${RELEASE_DIR}; tests skipped.`,
  )
}

const itLR = binaryMissing || releaseDirMissing ? test.skip : test

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const EXPECTED_STAGED_FILES = [
  'Groth16Verifier.sol',
  'circuit.ar1cs',
  'config.json',
  'manifest.json',
  'pk.bin',
  'pvk.bin',
  'vk.bin',
  'witness_gen.wasm',
].sort()

function sha256File(path: string): string {
  const hash = createHash('sha256')
  hash.update(readFileSync(path))
  return hash.digest('hex')
}

/**
 * Copy the release directory to a fresh tmpdir so we can mutate it
 * without polluting the real release bundle. Uses `cp -R` (portable on
 * macOS + Linux) which is fast for our ~700MB pk.bin via APFS clone on
 * macOS and copy-on-write on modern Linux file systems.
 */
function copyReleaseDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'zkap-release-copy-'))
  execSync(`cp -R "${RELEASE_DIR}/." "${dir}/"`, { stdio: 'ignore' })
  return dir
}

// Track staged tmpdirs for cleanup (best-effort).
const stagedTmpdirsToCleanup: string[] = []

test.after.always(() => {
  for (const dir of stagedTmpdirsToCleanup) {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      /* best-effort */
    }
  }
})

/**
 * Purge any warm cache entries under os.tmpdir() for the given shape.
 *
 * loadRelease's cache key is derived from `<shape>-SHA256SUMS` content,
 * which mutation tests below do NOT touch (they only mutate artifact
 * files in a fresh copy). Without purging the warm cache, the cache key
 * computed from the unmodified SHA256SUMS would hit the existing
 * canonical staged dir and loadRelease would return success — bypassing
 * the integrity-failure path that the mutation test is exercising.
 *
 * Purging forces the cold-stage path which actually reads the (polluted)
 * source files and triggers the intended error.
 */
function purgeWarmCacheForShape(shape: string): void {
  const tmpRoot = tmpdir()
  let entries: string[] = []
  try {
    entries = readdirSync(tmpRoot)
  } catch {
    return
  }
  const suffix = `-${shape}`
  for (const name of entries) {
    if (name.startsWith('zkap-release-') && (name.endsWith(suffix) || name.endsWith(`${suffix}.lock`) || name.endsWith(`${suffix}.tmp`))) {
      try {
        rmSync(join(tmpRoot, name), { recursive: true, force: true })
      } catch {
        /* best-effort */
      }
    }
  }
}

function releaseShaForShape(shape: string): string {
  return createHash('sha256')
    .update(readFileSync(join(RELEASE_DIR, `${shape}-SHA256SUMS`)))
    .digest('hex')
    .slice(0, 16)
}

function rewriteSumsEntry(
  releaseDir: string,
  shape: string,
  artifactName: string,
  sha256: string,
): void {
  const sumsPath = join(releaseDir, `${shape}-SHA256SUMS`)
  const lines = readFileSync(sumsPath, 'utf8').split(/\r?\n/)
  let changed = false
  const rewritten = lines.map((line) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return line
    const parts = trimmed.split(/\s+/)
    const name = parts[parts.length - 1]?.replace(/^\*/, '')
    if (name !== artifactName) return line
    changed = true
    return `${sha256}  ${artifactName}`
  })
  if (!changed) {
    throw new Error(`${shape}-SHA256SUMS missing ${artifactName}`)
  }
  writeFileSync(sumsPath, rewritten.join('\n'))
}

function readManifestCircuitCommit(releaseDir: string, shape: string): string {
  const manifest = JSON.parse(
    readFileSync(join(releaseDir, `${shape}-manifest.json`), 'utf8'),
  ) as { build?: { circuit_commit?: unknown } }
  const commit = manifest.build?.circuit_commit
  if (typeof commit !== 'string') {
    throw new Error(`${shape}-manifest.json missing build.circuit_commit`)
  }
  return commit
}

function rewriteManifest(
  releaseDir: string,
  shape: string,
  update: (manifest: Record<string, unknown>) => void,
): void {
  const manifestPath = join(releaseDir, `${shape}-manifest.json`)
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>
  update(manifest)
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`
  writeFileSync(manifestPath, manifestText)
  rewriteSumsEntry(
    releaseDir,
    shape,
    'manifest.json',
    createHash('sha256').update(manifestText).digest('hex'),
  )
}

function loadFixtureRelease(opts: {
  releaseDir?: string
  shape: string
}) {
  return loadRelease({
    releaseDir: opts.releaseDir ?? RELEASE_DIR,
    shape: opts.shape,
    allowCircuitCommitMismatch: true,
  })
}

// ---------------------------------------------------------------------------
// (a) 1-of-1 success
// ---------------------------------------------------------------------------
itLR('(a) loadRelease({shape: "1-of-1"}) returns staged 8-file bundle', (t) => {
  const result = loadFixtureRelease({ shape: '1-of-1' })

  t.is(typeof result.stagedDir, 'string')
  t.is(typeof result.manifestJson, 'string')
  t.is(result.shape, '1-of-1')
  t.regex(result.releaseSha, /^[0-9a-f]{16}$/)

  const actualFiles = readdirSync(result.stagedDir)
    .filter((f) => !f.endsWith('.lock'))
    .sort()
  t.deepEqual(actualFiles, EXPECTED_STAGED_FILES)

  const manifest = JSON.parse(result.manifestJson) as Record<string, unknown>
  t.is(manifest['manifest_version'], '1')
  t.is(manifest['curve'], 'bn254')
})

itLR('(a2) loadRelease accepts an explicit zkap-circuit commit pin', (t) => {
  const circuitCommit = readManifestCircuitCommit(RELEASE_DIR, '1-of-1')
  const result = loadRelease({
    releaseDir: RELEASE_DIR,
    shape: '1-of-1',
    expectedCircuitCommit: circuitCommit.slice(0, 12),
  })

  const manifest = JSON.parse(result.manifestJson) as {
    build: { circuit_commit: string }
  }
  t.is(manifest.build.circuit_commit, circuitCommit)
})

itLR('(a3) loadRelease rejects a zkap-circuit commit mismatch', (t) => {
  purgeWarmCacheForShape('1-of-1')
  const copied = copyReleaseDir()
  stagedTmpdirsToCleanup.push(copied)
  rewriteManifest(copied, '1-of-1', (manifest) => {
    const build = (manifest['build'] ?? {}) as Record<string, unknown>
    build['circuit_commit'] = '0000000000000000000000000000000000000000'
    manifest['build'] = build
  })

  const err = t.throws(
    () => loadRelease({ releaseDir: copied, shape: '1-of-1' }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
  t.regex(err!.message, /release commit mismatch|build\.circuit_commit/i)
})

// ---------------------------------------------------------------------------
// (b) 3-of-3 success
// ---------------------------------------------------------------------------
itLR('(b) loadRelease({shape: "3-of-3"}) returns staged 8-file bundle', (t) => {
  const result = loadFixtureRelease({ shape: '3-of-3' })

  t.is(result.shape, '3-of-3')
  t.regex(result.releaseSha, /^[0-9a-f]{16}$/)

  const actualFiles = readdirSync(result.stagedDir)
    .filter((f) => !f.endsWith('.lock'))
    .sort()
  t.deepEqual(actualFiles, EXPECTED_STAGED_FILES)

  const manifest = JSON.parse(result.manifestJson) as Record<string, unknown>
  t.is(manifest['manifest_version'], '1')
})

itLR('(b2) loadRelease repairs an incomplete warm-cache directory', (t) => {
  const shape = '3-of-3'
  purgeWarmCacheForShape(shape)

  const releaseSha = releaseShaForShape(shape)
  const stagedDir = join(tmpdir(), `zkap-release-${releaseSha}-${shape}`)
  mkdirSync(stagedDir, { recursive: true })

  const result = loadFixtureRelease({ shape })
  t.is(result.stagedDir, stagedDir)

  const actualFiles = readdirSync(result.stagedDir)
    .filter((f) => !f.endsWith('.lock'))
    .sort()
  t.deepEqual(actualFiles, EXPECTED_STAGED_FILES)
})

// ---------------------------------------------------------------------------
// (c) missing releaseDir
// ---------------------------------------------------------------------------
itLR('(c) loadRelease throws when releaseDir does not exist', (t) => {
  const err = t.throws(
    () =>
      loadRelease({
        releaseDir: '/tmp/zkap-this-release-dir-does-not-exist-xyz',
        shape: '1-of-1',
      }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
})

// ---------------------------------------------------------------------------
// (d) missing prefix file
// ---------------------------------------------------------------------------
itLR('(d) loadRelease throws MissingArtifact when prefix file is absent', (t) => {
  purgeWarmCacheForShape('1-of-1')
  const copied = copyReleaseDir()
  stagedTmpdirsToCleanup.push(copied)
  rmSync(join(copied, '1-of-1-pk.bin'), { force: true })

  const err = t.throws(
    () => loadFixtureRelease({ releaseDir: copied, shape: '1-of-1' }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
  t.regex(err!.message, /pk\.bin|MissingArtifact/i)
})

// ---------------------------------------------------------------------------
// (e) SHA mismatch
// ---------------------------------------------------------------------------
itLR('(e) loadRelease throws IntegrityFailure on SHA mismatch', (t) => {
  purgeWarmCacheForShape('1-of-1')
  const copied = copyReleaseDir()
  stagedTmpdirsToCleanup.push(copied)

  // Flip one byte at the very start of pk.bin so SHA changes but file size stays.
  const target = join(copied, '1-of-1-pk.bin')
  const buf = readFileSync(target)
  buf[0] = buf[0] ^ 0xff
  writeFileSync(target, buf)

  const err = t.throws(
    () => loadFixtureRelease({ releaseDir: copied, shape: '1-of-1' }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
  t.regex(err!.message, /expected.*got|IntegrityFailure/i)
})

// ---------------------------------------------------------------------------
// (f) malformed manifest
// ---------------------------------------------------------------------------
itLR('(f) loadRelease throws MalformedManifest on invalid JSON', (t) => {
  purgeWarmCacheForShape('1-of-1')
  const copied = copyReleaseDir()
  stagedTmpdirsToCleanup.push(copied)
  writeFileSync(join(copied, '1-of-1-manifest.json'), '{ not valid json')

  const err = t.throws(
    () => loadFixtureRelease({ releaseDir: copied, shape: '1-of-1' }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
  t.regex(err!.message, /MalformedManifest|parse|json/i)
})

itLR('(f2) loadRelease rejects legacy manifests without witness_gen.wasm', (t) => {
  purgeWarmCacheForShape('1-of-1')
  const copied = copyReleaseDir()
  stagedTmpdirsToCleanup.push(copied)

  const manifestPath = join(copied, '1-of-1-manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
    artifacts?: Record<string, unknown>
  }
  delete manifest.artifacts?.witness_gen
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`
  writeFileSync(manifestPath, manifestText)
  rewriteSumsEntry(
    copied,
    '1-of-1',
    'manifest.json',
    createHash('sha256').update(manifestText).digest('hex'),
  )

  const err = t.throws(
    () => loadFixtureRelease({ releaseDir: copied, shape: '1-of-1' }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
  t.regex(err!.message, /incompatible|witness_gen\.wasm|artifacts\.witness_gen/i)
})

// ---------------------------------------------------------------------------
// (g) unknown shape
// ---------------------------------------------------------------------------
itLR('(g) loadRelease throws UnknownShape on invalid shape', (t) => {
  const err = t.throws(
    () => loadRelease({ releaseDir: RELEASE_DIR, shape: '2-of-2' }),
    { instanceOf: Error },
  )
  t.regex(err!.message, /loadRelease:/)
  t.regex(err!.message, /UnknownShape|2-of-2|shape/i)
})

// ---------------------------------------------------------------------------
// (h) idempotent re-call
// ---------------------------------------------------------------------------
itLR('(h) loadRelease is idempotent (same stagedDir, warm-cache < 2s)', (t) => {
  // Cold call (may already be warm from earlier tests — that's fine).
  const r1 = loadFixtureRelease({ shape: '1-of-1' })

  // Warm call.
  const tStart = Date.now()
  const r2 = loadFixtureRelease({ shape: '1-of-1' })
  const warmMs = Date.now() - tStart

  t.is(r1.stagedDir, r2.stagedDir)
  t.is(r1.releaseSha, r2.releaseSha)
  t.true(warmMs < 2000, `warm-cache call took ${warmMs}ms (must be < 2000ms)`)
})

// ---------------------------------------------------------------------------
// (i) concurrent calls — 4 parallel resolutions
// ---------------------------------------------------------------------------
itLR('(i) loadRelease concurrent calls converge on same stagedDir', async (t) => {
  // Pre-warm so the test focuses on lock-mediated concurrency, not first-bake races.
  const warm = loadFixtureRelease({ shape: '1-of-1' })

  // 4 parallel calls using Promise.all over synchronous loadRelease.
  // (Even though loadRelease is sync in JS, ava's worker model exercises it
  //  serially within this test — the real concurrency guarantee is enforced
  //  by the Rust-side fs2 lock during cold staging. Pre-warming exercises the
  //  warm-cache fast path under repeated invocation.)
  const results = await Promise.all([
    Promise.resolve().then(() => loadFixtureRelease({ shape: '1-of-1' })),
    Promise.resolve().then(() => loadFixtureRelease({ shape: '1-of-1' })),
    Promise.resolve().then(() => loadFixtureRelease({ shape: '1-of-1' })),
    Promise.resolve().then(() => loadFixtureRelease({ shape: '1-of-1' })),
  ])

  for (const r of results) {
    t.is(r.stagedDir, warm.stagedDir)
    t.is(r.releaseSha, warm.releaseSha)
  }

  // Verify the final staged pk.bin is uncorrupted vs the manifest's expected SHA.
  const manifest = JSON.parse(warm.manifestJson) as {
    artifacts: { pk: { sha256: string } }
  }
  const actualPkSha = sha256File(join(warm.stagedDir, 'pk.bin'))
  t.is(actualPkSha, manifest.artifacts.pk.sha256)
})
