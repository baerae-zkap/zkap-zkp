/**
 * NAPI-level tests for the post-refactor `prove(config, request)` surface.
 *
 * The Rust signature now takes a `manifestDir` and a structured
 * `credentials[]` array (one entry per JWT) instead of the legacy
 * `pkPath` + parallel arrays. Validation lives in the loader (manifest
 * SHA checks) and the prover adapter (shape gates on
 * `credentials.len() == k`, `merkle_path.len() == tree_height`, etc.).
 *
 * Categories:
 *   1. Wiring smoke         — load a real CRS bundle from
 *                             `ZKAP_PROOF_MANIFEST_DIR` (default:
 *                             `<repo>/../zkap-circuit/dist/1-of-1`) and
 *                             call `prove()` with a placeholder request
 *                             that satisfies shape gates. The witness
 *                             layer rejects garbage, so the call must
 *                             return an Error — proving NAPI ↔
 *                             ArtifactSet ↔ adapter ↔ witness layer is
 *                             wired.
 *   2. Loader negatives     — nonexistent manifest dir, missing
 *                             manifest.json.
 *   3. Adapter shape gates  — wrong number of credentials, wrong
 *                             merkle_path length, leaf index out of
 *                             range.
 *   4. Happy path (opt-in)  — when `ZKAP_PROOF_FIXTURE_JSON` points at
 *                             a JSON file produced by the fixture
 *                             generator, run the full prove flow and
 *                             check structural invariants. The
 *                             `*_JSON` variable feeds the **native
 *                             synthesize** path (bundle without
 *                             `witness_gen.wasm`). The
 *                             `ZKAP_PROOF_FIXTURE_WASM_JSON`
 *                             variable feeds the **wasm synthesize**
 *                             path (bundle with `witness_gen.wasm`
 *                             registered in `manifest.json`). Both
 *                             happy-path tests are independently
 *                             gated and `test.skip` when their
 *                             fixture is missing — opt-in so CI
 *                             without a built wasm doesn't fail.
 *
 * Run after building the native binary:
 *   npm run build:debug && npm test
 *
 * The same scenarios are duplicated in `../test-bdd/prove.spec.ts`
 * as a mocha + chai BDD-style specification for human-readable docs.
 */

import test from 'ava'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------
const PACKAGE_ROOT = resolve(import.meta.dirname ?? __dirname, '..')
const INDEX_JS = resolve(PACKAGE_ROOT, 'index.js')

const binaryMissing = !existsSync(INDEX_JS)
if (binaryMissing) {
  console.warn('[proof.spec.ts] Native binary not found; run `npm run build`. All tests skipped.')
}

const bindings = binaryMissing ? null : await import(INDEX_JS)
const prove = bindings?.prove
const verify = bindings?.verify

const it = binaryMissing ? test.skip : test

// ---------------------------------------------------------------------------
// Locate the smoke-test manifest dir
// ---------------------------------------------------------------------------
// Default: sibling zkap-circuit checkout's `dist/1-of-1` bundle.
// Override with ZKAP_PROOF_MANIFEST_DIR if you have a different CRS to point at.
const DEFAULT_MANIFEST_DIR = resolve(PACKAGE_ROOT, '../../../zkap-circuit/dist/1-of-1')
const MANIFEST_DIR = process.env['ZKAP_PROOF_MANIFEST_DIR'] ?? DEFAULT_MANIFEST_DIR

const manifestDirMissing =
  !existsSync(join(MANIFEST_DIR, 'manifest.json')) ||
  !existsSync(join(MANIFEST_DIR, 'pk.bin')) ||
  !existsSync(join(MANIFEST_DIR, 'circuit.ar1cs'))

if (manifestDirMissing && !binaryMissing) {
  console.warn(
    `[proof.spec.ts] CRS bundle not found at ${MANIFEST_DIR}; smoke + adapter-gate tests skipped.`,
  )
}

const itWithCrs = binaryMissing || manifestDirMissing ? test.skip : test

// Lazily read the circuit config from the bundle so the placeholder request
// matches the bundle's `n / k / tree_height`.
type CircuitParams = {
  maxJwtB64Len: number
  maxPayloadB64Len: number
  maxAudLen: number
  maxExpLen: number
  maxIssLen: number
  maxNonceLen: number
  maxSubLen: number
  n: number
  k: number
  treeHeight: number
  numAudienceLimit: number
  claims: string[]
  forbiddenString: string
}

const CONFIG: CircuitParams | null = manifestDirMissing
  ? null
  : (() => {
      const raw = JSON.parse(
        readFileSync(join(MANIFEST_DIR, 'config.json'), 'utf8'),
      ) as Record<string, unknown>
      return {
        maxJwtB64Len: raw.max_jwt_b64_len as number,
        maxPayloadB64Len: raw.max_payload_b64_len as number,
        maxAudLen: raw.max_aud_len as number,
        maxExpLen: raw.max_exp_len as number,
        maxIssLen: raw.max_iss_len as number,
        maxNonceLen: raw.max_nonce_len as number,
        maxSubLen: raw.max_sub_len as number,
        n: raw.n as number,
        k: raw.k as number,
        treeHeight: raw.tree_height as number,
        numAudienceLimit: raw.num_audience_limit as number,
        claims: raw.claims as string[],
        forbiddenString: raw.forbidden_string as string,
      }
    })()

// ---------------------------------------------------------------------------
// Placeholder fixture builders
// ---------------------------------------------------------------------------
// Mirrors `crates/service/tests/native_prove_e2e.rs::placeholder_prove_request`:
// shape-valid garbage. The adapter accepts it long enough to reach (or
// fail just before) the witness layer.

const ZERO_FE = '0x00'

/** 256-byte RSA modulus (all 0xAA) base64-encoded. */
const PLACEHOLDER_RSA_MODULUS_B64 = Buffer.alloc(256, 0xaa).toString('base64')

/**
 * `header.payload.signature` — header `{"alg":"RS256","typ":"JWT"}`,
 * payload with `aud/iss/sub/exp`, signature 256 × 0xAA. Junk content,
 * length-valid.
 */
function placeholderJwt(): string {
  const header = Buffer.from('{"alg":"RS256","typ":"JWT"}').toString('base64url')
  const payload = Buffer.from('{"aud":"a","iss":"i","sub":"s","exp":1700000000}').toString(
    'base64url',
  )
  const sig = Buffer.alloc(256, 0xaa).toString('base64url')
  return `${header}.${payload}.${sig}`
}

function placeholderRequest(cfg: CircuitParams) {
  const k = cfg.k
  const anchorLen = cfg.n - cfg.k + 1
  const th = cfg.treeHeight

  return {
    manifestDir: MANIFEST_DIR,
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

// ---------------------------------------------------------------------------
// 1. Wiring smoke
// ---------------------------------------------------------------------------

itWithCrs(
  'prove: wiring smoke — real manifest dir + placeholder request rejected by witness/adapter',
  (t) => {
    t.timeout(120_000)
    t.truthy(CONFIG)
    const req = placeholderRequest(CONFIG!)
    // The release witness wasm or request adapter returns Err on garbage
    // input; the binding maps that to a thrown Error. We don't care
    // which downstream layer rejects, only that the load → adapter →
    // witness pipeline is wired
    // and the failure surfaces as an exception (not a panic, not a
    // success).
    const err = t.throws(() => prove(CONFIG, req), { instanceOf: Error })
    t.truthy(err?.message, 'error must carry a non-empty message')
  },
)

// ---------------------------------------------------------------------------
// 2. Loader negatives
// ---------------------------------------------------------------------------

it('prove: nonexistent manifest dir throws', (t) => {
  const req = {
    manifestDir: '/tmp/zkap-this-path-does-not-exist',
    random: ZERO_FE,
    hSignUserOp: ZERO_FE,
    anchor: [ZERO_FE],
    merkleRoot: ZERO_FE,
    credentials: [
      {
        jwt: placeholderJwt(),
        rsaModulusB64: PLACEHOLDER_RSA_MODULUS_B64,
        merklePath: [ZERO_FE],
        merkleLeafIdx: 0,
      },
    ],
  }
  // Pass a dummy config — `prove` ignores it and loads CircuitConfig from
  // the manifest dir, but napi requires the param to be shape-valid.
  t.throws(() => prove(dummyConfig(), req), { instanceOf: Error })
})

it('prove: manifest dir missing manifest.json throws', (t) => {
  const emptyDir = mkdtempSync(join(tmpdir(), 'zkap-empty-manifest-'))
  const req = {
    manifestDir: emptyDir,
    random: ZERO_FE,
    hSignUserOp: ZERO_FE,
    anchor: [ZERO_FE],
    merkleRoot: ZERO_FE,
    credentials: [
      {
        jwt: placeholderJwt(),
        rsaModulusB64: PLACEHOLDER_RSA_MODULUS_B64,
        merklePath: [ZERO_FE],
        merkleLeafIdx: 0,
      },
    ],
  }
  t.throws(() => prove(dummyConfig(), req), { instanceOf: Error })
})

it('prove: manifest dir with malformed manifest.json throws', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'zkap-bad-manifest-'))
  writeFileSync(join(dir, 'manifest.json'), '{ not valid json')
  const req = {
    manifestDir: dir,
    random: ZERO_FE,
    hSignUserOp: ZERO_FE,
    anchor: [ZERO_FE],
    merkleRoot: ZERO_FE,
    credentials: [
      {
        jwt: placeholderJwt(),
        rsaModulusB64: PLACEHOLDER_RSA_MODULUS_B64,
        merklePath: [ZERO_FE],
        merkleLeafIdx: 0,
      },
    ],
  }
  t.throws(() => prove(dummyConfig(), req), { instanceOf: Error })
})

// ---------------------------------------------------------------------------
// 3. Adapter shape gates (require a real manifest dir to get past loader)
// ---------------------------------------------------------------------------

itWithCrs('prove: wrong number of credentials throws (credentials.len != k)', (t) => {
  const cfg = CONFIG!
  const req = placeholderRequest(cfg)
  req.credentials = [...req.credentials, ...req.credentials] // 2x → mismatch
  t.throws(() => prove(cfg, req), { instanceOf: Error })
})

itWithCrs('prove: wrong merkle_path length throws (path.len != tree_height)', (t) => {
  const cfg = CONFIG!
  const req = placeholderRequest(cfg)
  // truncate every credential's merkle_path
  req.credentials = req.credentials.map((c) => ({ ...c, merklePath: c.merklePath.slice(0, -1) }))
  t.throws(() => prove(cfg, req), { instanceOf: Error })
})

itWithCrs('prove: merkle_leaf_idx out of range throws', (t) => {
  const cfg = CONFIG!
  const req = placeholderRequest(cfg)
  // 2^tree_height is the exclusive upper bound; pick something safely past it.
  const oob = Math.min(Number.MAX_SAFE_INTEGER, 2 ** Math.min(cfg.treeHeight, 30) + 1)
  req.credentials = req.credentials.map((c) => ({ ...c, merkleLeafIdx: oob }))
  t.throws(() => prove(cfg, req), { instanceOf: Error })
})

// ---------------------------------------------------------------------------
// 4. Happy path (opt-in, fixture-driven, release witness wasm)
// ---------------------------------------------------------------------------
//
// Drop a JSON file at the path given by ZKAP_PROOF_FIXTURE_JSON (or
// ZKAP_PROOF_FIXTURE_WASM_JSON) with shape:
//   {
//     "manifestDir": "<abs path to a CRS bundle>",
//     "config":      { ... JsCircuitConfig fields ... },
//     "request":     { ... JsProofRequest fields without manifestDir ... }
//   }
// `config.n / .k / .treeHeight` must match `manifestDir`'s `config.json`.
//
// The supported happy path uses ZKAP_PROOF_FIXTURE_WASM_JSON: a release
// bundle with witness_gen.wasm registered in manifest.json.
// Each test independently `test.skip`'s when its fixture is missing.

type ProofFixture = {
  manifestDir: string
  config: CircuitParams
  request: Omit<ReturnType<typeof placeholderRequest>, 'manifestDir'>
}

function manifestHasWitnessGen(manifestDir: string): boolean {
  try {
    const m = JSON.parse(readFileSync(join(manifestDir, 'manifest.json'), 'utf8')) as {
      artifacts?: Record<string, unknown>
    }
    return !!m.artifacts && 'witness_gen' in m.artifacts
  } catch {
    return false
  }
}

function runHappyPath(
  t: import('ava').ExecutionContext,
  fixturePath: string,
  opts: { expectWitnessGen: boolean },
): void {
  t.timeout(600_000)
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as ProofFixture
  const hasWasm = manifestHasWitnessGen(fixture.manifestDir)
  t.is(
    hasWasm,
    opts.expectWitnessGen,
    opts.expectWitnessGen
      ? `bundle at ${fixture.manifestDir} should register witness_gen in manifest.json`
      : `bundle at ${fixture.manifestDir} should not register witness_gen in manifest.json`,
  )

  const req = { ...fixture.request, manifestDir: fixture.manifestDir }
  const out = prove(fixture.config, req)

  const k = fixture.config.k
  t.true(Array.isArray(out.proofs), 'proofs is an array')
  t.is(out.proofs.length, k, 'one proof per credential')
  for (const p of out.proofs) {
    t.is(p.length, 8, 'each proof has 8 Solidity field elements')
  }
  t.is(out.sharedInputs.length, 6, 'six shared public inputs')
  t.is(out.partialRhsList.length, k, 'partial_rhs per credential')
  t.is(out.jwtExpList.length, k, 'jwt_exp per credential')

  // Cryptographic check: every proof must verify against the bundle's
  // PreparedVerifyingKey. Tampering coverage lives in the dedicated
  // negative test below so this stays focused on the happy path.
  const v = verify(fixture.manifestDir, out)
  t.is(v.results.length, k, 'one verdict per proof')
  for (const ok of v.results) t.true(ok, 'proof must verify against pvk')
  t.true(v.allValid, 'allValid must be true for an honest proof bundle')
}

// — Missing wasm negative path —
const NATIVE_FIXTURE_PATH = process.env['ZKAP_PROOF_FIXTURE_JSON']
const nativeFixtureMissing = !NATIVE_FIXTURE_PATH || !existsSync(NATIVE_FIXTURE_PATH)

if (NATIVE_FIXTURE_PATH && nativeFixtureMissing) {
  console.warn(
    `[proof.spec.ts] ZKAP_PROOF_FIXTURE_JSON=${NATIVE_FIXTURE_PATH} not found; missing-wasm negative path skipped.`,
  )
}

const itMissingWasm = binaryMissing || nativeFixtureMissing ? test.skip : test

itMissingWasm('prove: fixture without witness_gen.wasm is rejected', (t) => {
  const fixture = JSON.parse(readFileSync(NATIVE_FIXTURE_PATH!, 'utf8')) as ProofFixture
  t.false(
    manifestHasWitnessGen(fixture.manifestDir),
    `bundle at ${fixture.manifestDir} should not register witness_gen in manifest.json`,
  )
  const req = { ...fixture.request, manifestDir: fixture.manifestDir }
  const err = t.throws(() => prove(fixture.config, req))
  t.regex(String(err?.message ?? err), /witness_gen\.wasm/)
})

// — Wasm synthesize path —
const WASM_FIXTURE_PATH = process.env['ZKAP_PROOF_FIXTURE_WASM_JSON']
const wasmFixtureMissing = !WASM_FIXTURE_PATH || !existsSync(WASM_FIXTURE_PATH)

if (WASM_FIXTURE_PATH && wasmFixtureMissing) {
  console.warn(
    `[proof.spec.ts] ZKAP_PROOF_FIXTURE_WASM_JSON=${WASM_FIXTURE_PATH} not found; wasm happy path skipped.`,
  )
}

const itHappyWasm = binaryMissing || wasmFixtureMissing ? test.skip : test

itHappyWasm(
  'prove: fixture (wasm synthesize) produces a structurally valid proof bundle',
  (t) => runHappyPath(t, WASM_FIXTURE_PATH!, { expectWitnessGen: true }),
)

// — Negative cryptographic check: tampering breaks verification —
const itTamper = binaryMissing || wasmFixtureMissing ? test.skip : test

itTamper('verify: rejects a proof whose shared `hanchor` was tampered with', (t) => {
  t.timeout(600_000)
  const fixture = JSON.parse(readFileSync(WASM_FIXTURE_PATH!, 'utf8')) as ProofFixture
  const req = { ...fixture.request, manifestDir: fixture.manifestDir }
  const out = prove(fixture.config, req)

  // Control: untampered out must verify.
  t.true(verify(fixture.manifestDir, out).allValid, 'control: honest proof must verify')

  // Flip one nibble of the first shared public input (`hanchor`) and
  // re-verify. The proof was bound to the original `hanchor`, so the
  // pairing equation must reject.
  const sharedInputsTampered = [...out.sharedInputs]
  const orig = sharedInputsTampered[0]
  const flipped = orig.slice(0, -1) + (orig.at(-1) === '0' ? '1' : '0')
  sharedInputsTampered[0] = flipped
  const tampered = { ...out, sharedInputs: sharedInputsTampered }

  const v = verify(fixture.manifestDir, tampered)
  t.false(v.allValid, 'tampered hanchor must drop allValid to false')
  for (const ok of v.results) t.false(ok, 'every proof bound to the tampered hanchor must reject')
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal JsCircuitConfig — `prove` ignores its fields but napi validates shape. */
function dummyConfig(): CircuitParams {
  return {
    maxJwtB64Len: 1024,
    maxPayloadB64Len: 640,
    maxAudLen: 155,
    maxExpLen: 20,
    maxIssLen: 93,
    maxNonceLen: 93,
    maxSubLen: 93,
    n: 1,
    k: 1,
    treeHeight: 1,
    numAudienceLimit: 5,
    claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
    forbiddenString: 'forbidden',
  }
}
