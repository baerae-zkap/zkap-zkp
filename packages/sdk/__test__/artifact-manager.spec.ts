/**
 * Tests for artifact-manager.ts
 *
 * Covers:
 *   - getCachedPkPath: file-exists / file-missing
 *   - initArtifacts: manifest validation, version checks, cache hit, cache miss,
 *     stale cache, and retry on 5xx
 *
 * Network is fully mocked via globalThis.fetch.
 * Real temporary files are used for SHA256 verification.
 *
 * All tests run serially to avoid globalThis.fetch mock interference.
 */

import test from 'ava'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'
import { getCachedPkPath, initArtifacts } from '../src/artifact-manager'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Compute the SHA256 hex digest of a Buffer. */
function sha256Hex(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex')
}

/**
 * Build a minimal valid ArtifactManifest JSON object.
 * The default proving key content is `pkContent` so sha256 always matches
 * the data returned by `makePkFetch`.
 */
function makeManifest(
  pkContent: Buffer,
  overrides: Record<string, unknown> = {},
  pkOverrides: Record<string, unknown> = {},
) {
  return {
    version: '0.1.0',
    circuit: 'test-circuit',
    min_sdk_version: '0.1.0',
    max_sdk_version: '0.1.x',
    artifacts: {
      proving_key: {
        url: 'https://example.com/test-circuit-pk.bin',
        sha256: sha256Hex(pkContent),
        size_bytes: pkContent.byteLength,
        ...pkOverrides,
      },
    },
    ...overrides,
  }
}

/** Create a Response that streams `data` as the body. */
function binaryResponse(data: Buffer, status = 200): Response {
  return new Response(data, {
    status,
    headers: { 'Content-Length': String(data.byteLength) },
  })
}

/**
 * Build a fetch mock that:
 *   - Returns `manifest` as JSON for the manifest URL
 *   - Calls `artifactFetch(callCount)` for all other URLs
 *     where `callCount` increments on each artifact request
 */
function makeFetch(
  manifest: unknown,
  artifactFetch: (callCount: number) => Response,
): { mock: typeof globalThis.fetch; getArtifactCallCount: () => number } {
  let artifactCallCount = 0
  const mock: typeof globalThis.fetch = async (url) => {
    const urlStr = String(url)
    if (urlStr.includes('manifest')) {
      return new Response(JSON.stringify(manifest), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    artifactCallCount++
    return artifactFetch(artifactCallCount)
  }
  return { mock, getArtifactCallCount: () => artifactCallCount }
}

/** Install a fetch mock for the duration of one test and restore afterwards. */
function useFetch(
  t: import('ava').ExecutionContext,
  impl: typeof globalThis.fetch,
) {
  const original = globalThis.fetch
  globalThis.fetch = impl
  t.teardown(() => {
    globalThis.fetch = original
  })
}

// ---------------------------------------------------------------------------
// getCachedPkPath
// ---------------------------------------------------------------------------

test.serial('getCachedPkPath: returns null when file does not exist', (t) => {
  const result = getCachedPkPath('/tmp/no-such-dir-zkap-test-xyz', 'missing-circuit')
  t.is(result, null)
})

test.serial('getCachedPkPath: returns path when file exists', async (t) => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const circuit = 'my-circuit'
  const pkPath = path.join(tmpDir, `${circuit}-pk.bin`)
  await fs.writeFile(pkPath, Buffer.from('pk-data'))

  const result = getCachedPkPath(tmpDir, circuit)
  t.is(result, pkPath)
})

// ---------------------------------------------------------------------------
// initArtifacts — manifest validation
// ---------------------------------------------------------------------------

test.serial('initArtifacts: throws when manifest is missing circuit field', async (t) => {
  const pkContent = Buffer.from('fake-pk-bytes')
  const manifest = makeManifest(pkContent, { circuit: '' })

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  await t.throwsAsync(
    () => initArtifacts({ manifestUrl: 'https://example.com/manifest.json', cacheDir: tmpDir }),
    { message: /missing required fields/ },
  )
})

test.serial('initArtifacts: throws when manifest is missing proving_key.url', async (t) => {
  const pkContent = Buffer.from('fake-pk-bytes')
  const manifest = makeManifest(pkContent, {}, { url: '' })

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  await t.throwsAsync(
    () => initArtifacts({ manifestUrl: 'https://example.com/manifest.json', cacheDir: tmpDir }),
    { message: /missing required fields/ },
  )
})

test.serial('initArtifacts: throws when manifest is missing proving_key.sha256', async (t) => {
  const pkContent = Buffer.from('fake-pk-bytes')
  const manifest = makeManifest(pkContent, {}, { sha256: '' })

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  await t.throwsAsync(
    () => initArtifacts({ manifestUrl: 'https://example.com/manifest.json', cacheDir: tmpDir }),
    { message: /missing required fields/ },
  )
})

// ---------------------------------------------------------------------------
// initArtifacts — SDK version check
// ---------------------------------------------------------------------------

test.serial('initArtifacts: throws when SDK version is below min_sdk_version', async (t) => {
  // SDK_VERSION is "0.1.0"; require minimum "0.2.0"
  const pkContent = Buffer.from('fake-pk-bytes')
  const manifest = makeManifest(pkContent, { min_sdk_version: '0.2.0', max_sdk_version: '1.0.0' })

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  await t.throwsAsync(
    () => initArtifacts({ manifestUrl: 'https://example.com/manifest.json', cacheDir: tmpDir }),
    { message: /below the minimum/ },
  )
})

test.serial('initArtifacts: throws when SDK version is above max_sdk_version', async (t) => {
  // SDK_VERSION is "0.1.0"; cap at "0.0.9"
  const pkContent = Buffer.from('fake-pk-bytes')
  const manifest = makeManifest(pkContent, { min_sdk_version: '0.0.1', max_sdk_version: '0.0.9' })

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  await t.throwsAsync(
    () => initArtifacts({ manifestUrl: 'https://example.com/manifest.json', cacheDir: tmpDir }),
    { message: /exceeds the maximum/ },
  )
})

test.serial('initArtifacts: passes version check when SDK version is within range', async (t) => {
  const pkContent = Buffer.from('range-ok-pk-bytes')
  const manifest = makeManifest(pkContent, { min_sdk_version: '0.0.1', max_sdk_version: '1.0.0' })

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  const result = await initArtifacts({
    manifestUrl: 'https://example.com/manifest.json',
    cacheDir: tmpDir,
  })

  t.true(result.endsWith('test-circuit-pk.bin'))
  t.true(result.startsWith(tmpDir))
})

// ---------------------------------------------------------------------------
// initArtifacts — cache hit
// ---------------------------------------------------------------------------

test.serial(
  'initArtifacts: returns cached path immediately when file exists and SHA256 matches',
  async (t) => {
    const pkContent = Buffer.from('cached-pk-bytes')
    const manifest = makeManifest(pkContent)

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
    t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

    // Pre-populate the cache with the correct file
    const pkPath = path.join(tmpDir, 'test-circuit-pk.bin')
    await fs.writeFile(pkPath, pkContent)

    let downloadCallMade = false
    const { mock } = makeFetch(manifest, () => {
      downloadCallMade = true
      return binaryResponse(pkContent)
    })
    useFetch(t, mock)

    const result = await initArtifacts({
      manifestUrl: 'https://example.com/manifest.json',
      cacheDir: tmpDir,
    })

    t.is(result, pkPath)
    t.false(downloadCallMade, 'No download should occur on cache hit')
  },
)

// ---------------------------------------------------------------------------
// initArtifacts — cache miss / stale
// ---------------------------------------------------------------------------

test.serial('initArtifacts: downloads when cache is missing', async (t) => {
  const pkContent = Buffer.from('fresh-pk-bytes')
  const manifest = makeManifest(pkContent)

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  const { mock, getArtifactCallCount } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  const result = await initArtifacts({
    manifestUrl: 'https://example.com/manifest.json',
    cacheDir: tmpDir,
  })

  t.is(getArtifactCallCount(), 1, 'Should have made exactly one download call')
  t.true(result.endsWith('test-circuit-pk.bin'))

  const stat = await fs.stat(result)
  t.true(stat.size > 0)
})

test.serial('initArtifacts: re-downloads when cached file has wrong SHA256', async (t) => {
  const pkContent = Buffer.from('correct-pk-bytes')
  const manifest = makeManifest(pkContent)

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
  t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

  // Write a stale/corrupted file with wrong content
  const pkPath = path.join(tmpDir, 'test-circuit-pk.bin')
  await fs.writeFile(pkPath, Buffer.from('stale-wrong-bytes'))

  const { mock, getArtifactCallCount } = makeFetch(manifest, () => binaryResponse(pkContent))
  useFetch(t, mock)

  const result = await initArtifacts({
    manifestUrl: 'https://example.com/manifest.json',
    cacheDir: tmpDir,
  })

  t.is(getArtifactCallCount(), 1, 'Should have made exactly one download call')
  t.is(result, pkPath)

  // Verify new content was written correctly
  const written = await fs.readFile(result)
  t.deepEqual(written, pkContent)
})

// ---------------------------------------------------------------------------
// initArtifacts — retry on 5xx
// ---------------------------------------------------------------------------

test.serial(
  'initArtifacts: retries on 5xx server error and succeeds on 3rd attempt',
  async (t) => {
    const pkContent = Buffer.from('retry-pk-bytes')
    const manifest = makeManifest(pkContent)

    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkap-test-'))
    t.teardown(() => fs.rm(tmpDir, { recursive: true, force: true }))

    const { mock, getArtifactCallCount } = makeFetch(manifest, (callCount) => {
      if (callCount < 3) {
        // First two attempts return 503
        return new Response('Service Unavailable', { status: 503 })
      }
      // Succeed on the 3rd attempt
      return binaryResponse(pkContent)
    })
    useFetch(t, mock)

    const result = await initArtifacts({
      manifestUrl: 'https://example.com/manifest.json',
      cacheDir: tmpDir,
    })

    t.is(getArtifactCallCount(), 3, 'Should have made exactly 3 artifact download attempts')
    t.true(result.endsWith('test-circuit-pk.bin'))
  },
)
