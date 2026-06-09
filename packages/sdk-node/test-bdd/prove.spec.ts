/**
 * Mocha BDD specification for `prove()` exposed by
 * `@baerae/zkap-zkp-node`.
 *
 * Scenarios mirror `__test__/proof.spec.ts` (same env-var contract for
 * the happy-path fixtures) but written as nested `describe` /
 * `context` / `it` blocks so the spec reads as a behaviour document.
 *
 * Happy-path tests are env-gated by ZKAP_PROOF_FIXTURE_WASM_JSON. Under
 * the new contract the CRS staged bundle no longer carries
 * `witness_gen.wasm`; the fixture supplies the witness generator via
 * `witnessGenPath` + `witnessGenSidecarPath` (whose sha256/compatibility
 * gates live in the Rust `load_witness_gen` layer, covered by Rust unit
 * tests + an e2e). ZKAP_PROOF_FIXTURE_JSON still drives the smoke +
 * adapter-gate suites. When the relevant env var is unset (or its file is
 * missing), the suite for that path calls `this.skip()` cleanly.
 */

import { expect } from 'chai'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  binaryMissing,
  loadBindings,
  skipIfBindingMissing,
} from './_support/bindings.js'
import {
  ProofFixture,
  loadFixture,
  placeholderJwt,
  placeholderRequest,
  PLACEHOLDER_RSA_MODULUS_B64,
} from './_support/fixtures.js'

type ProofOutput = {
  proofs: string[][]
  sharedInputs: string[]
  partialRhsList: string[]
  jwtExpList: string[]
}
type ProveFn = (config: unknown, request: unknown) => ProofOutput
type VerifyFn = (manifestDir: string, proofOutput: ProofOutput) => {
  results: boolean[]
  allValid: boolean
}

let prove: ProveFn
let verify: VerifyFn

function dummyConfig() {
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

const ZERO_FE = '0x00'

describe('@baerae/zkap-zkp-node • prove', function () {
  before(skipIfBindingMissing(this))

  before(async function () {
    if (binaryMissing) return
    const bindings = (await loadBindings()) as { prove: ProveFn; verify: VerifyFn }
    prove = bindings.prove
    verify = bindings.verify
  })

  describe('given a manifest directory', function () {
    context('when the directory does not exist', function () {
      it('throws synchronously with an Error', function () {
        expect(() =>
          prove(dummyConfig(), {
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
          }),
        ).to.throw(Error)
      })
    })

    context('when manifest.json is missing from the directory', function () {
      it('throws synchronously with an Error', function () {
        const dir = mkdtempSync(join(tmpdir(), 'zkap-empty-manifest-'))
        expect(() =>
          prove(dummyConfig(), {
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
          }),
        ).to.throw(Error)
      })
    })

    context('when manifest.json is malformed', function () {
      it('throws synchronously with an Error', function () {
        const dir = mkdtempSync(join(tmpdir(), 'zkap-bad-manifest-'))
        writeFileSync(join(dir, 'manifest.json'), '{ not valid json')
        expect(() =>
          prove(dummyConfig(), {
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
          }),
        ).to.throw(Error)
      })
    })
  })

  describe('given a real CRS bundle and a shape-valid placeholder request', function () {
    // These tests need a fixture to know which bundle to load. We reuse
    // the native fixture's `manifestDir`; if it's absent, skip.
    let fixture: ProofFixture | null
    before(function () {
      fixture = loadFixture('ZKAP_PROOF_FIXTURE_JSON')
      if (!fixture) {
        console.warn(
          '[prove.spec.ts] ZKAP_PROOF_FIXTURE_JSON missing; smoke + adapter-gate suites skipped.',
        )
        this.skip()
      }
    })

    context('with a garbage placeholder request', function () {
      it('reaches the witness/adapter layer and rejects', function () {
        this.timeout(180_000)
        const req = placeholderRequest(fixture!.config, fixture!.manifestDir)
        expect(() => prove(fixture!.config, req)).to.throw(Error)
      })
    })

    context('with the wrong number of credentials (length !== config.k)', function () {
      it('throws synchronously', function () {
        this.timeout(180_000)
        const req = placeholderRequest(fixture!.config, fixture!.manifestDir)
        req.credentials = [...req.credentials, ...req.credentials]
        expect(() => prove(fixture!.config, req)).to.throw(Error)
      })
    })

    context('with a merkle_path shorter than tree_height', function () {
      it('throws synchronously', function () {
        this.timeout(180_000)
        const req = placeholderRequest(fixture!.config, fixture!.manifestDir)
        req.credentials = req.credentials.map((c) => ({
          ...c,
          merklePath: c.merklePath.slice(0, -1),
        }))
        expect(() => prove(fixture!.config, req)).to.throw(Error)
      })
    })

    context('with merkle_leaf_idx >= 2 ** tree_height', function () {
      it('throws synchronously', function () {
        this.timeout(180_000)
        const cfg = fixture!.config
        const oob = Math.min(
          Number.MAX_SAFE_INTEGER,
          2 ** Math.min(cfg.treeHeight, 30) + 1,
        )
        const req = placeholderRequest(cfg, fixture!.manifestDir)
        req.credentials = req.credentials.map((c) => ({ ...c, merkleLeafIdx: oob }))
        expect(() => prove(cfg, req)).to.throw(Error)
      })
    })
  })

  describe('given a valid request and a real CRS bundle', function () {
    context('using the wasm synthesize path (app-supplied witness generator)', function () {
      let fixture: ProofFixture | null
      before(function () {
        fixture = loadFixture('ZKAP_PROOF_FIXTURE_WASM_JSON')
        if (!fixture) {
          console.warn(
            '[prove.spec.ts] ZKAP_PROOF_FIXTURE_WASM_JSON missing; wasm happy path skipped.',
          )
          this.skip()
        }
      })

      it('returns the proof shape and verifies against pvk', function () {
        this.timeout(600_000)
        const req = {
          ...fixture!.request,
          manifestDir: fixture!.manifestDir,
          witnessGenPath: fixture!.witnessGenPath,
          witnessGenSidecarPath: fixture!.witnessGenSidecarPath,
        }
        const out = prove(fixture!.config, req)
        const k = fixture!.config.k
        expect(out.proofs).to.be.an('array').with.length(k)
        for (const p of out.proofs) expect(p).to.have.length(8)
        expect(out.sharedInputs).to.have.length(6)
        expect(out.partialRhsList).to.have.length(k)
        expect(out.jwtExpList).to.have.length(k)

        const v = verify(fixture!.manifestDir, out)
        expect(v.allValid).to.equal(true)
        expect(v.results).to.have.length(k)
      })

      it('rejects verification when the shared hanchor is tampered with', function () {
        this.timeout(600_000)
        const req = {
          ...fixture!.request,
          manifestDir: fixture!.manifestDir,
          witnessGenPath: fixture!.witnessGenPath,
          witnessGenSidecarPath: fixture!.witnessGenSidecarPath,
        }
        const out = prove(fixture!.config, req)
        expect(verify(fixture!.manifestDir, out).allValid).to.equal(true)

        const sharedInputsTampered = [...out.sharedInputs]
        const orig = sharedInputsTampered[0]
        const flipped = orig.slice(0, -1) + (orig.at(-1) === '0' ? '1' : '0')
        sharedInputsTampered[0] = flipped
        const tampered = { ...out, sharedInputs: sharedInputsTampered }

        const v = verify(fixture!.manifestDir, tampered)
        expect(v.allValid).to.equal(false)
        for (const ok of v.results) expect(ok).to.equal(false)
      })
    })
  })
})
