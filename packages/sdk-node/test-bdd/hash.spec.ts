/**
 * Mocha BDD specification for hash helpers exposed by
 * `@baerae/zkap-zkp-sdk-node`.
 *
 * Same scenarios as `__test__/hash.spec.ts` but written as nested
 * `describe` / `context` / `it` blocks with English-sentence
 * expectations so the suite reads as a behaviour spec rather than a
 * test list.
 */

import { expect } from 'chai'

import { loadBindings, skipIfBindingMissing, binaryMissing } from './_support/bindings.js'
import {
  DEFAULT_CONFIG,
  DEFAULT_SECRET,
  DEFAULT_SECRETS,
  HEX_RE,
  PLACEHOLDER_RSA_MODULUS_B64,
} from './_support/fixtures.js'

type Bindings = {
  generateHash: (messages: string[]) => Promise<string>
  generateAnchor: (config: unknown, secrets: unknown) => Promise<{ evaluations: string[] }>
  generateAudHash: (
    config: unknown,
    audList: string[],
  ) => Promise<{ audHashes: string[]; hAudList: string }>
  generateLeafHash: (config: unknown, iss: string, pkB64: string) => Promise<string>
}

let g: Bindings

describe('@baerae/zkap-zkp-sdk-node • hash helpers', function () {
  before(skipIfBindingMissing(this))

  before(async function () {
    if (binaryMissing) return
    g = (await loadBindings()) as unknown as Bindings
  })

  describe('generateHash', function () {
    context('given a single numeric message', function () {
      it('returns a 0x-prefixed 256-bit hex string', async function () {
        const result = await g.generateHash(['12345'])
        expect(result).to.match(HEX_RE)
      })
    })

    context('given identical input twice', function () {
      it('is deterministic — same input yields the same digest', async function () {
        const a = await g.generateHash(['42', '99'])
        const b = await g.generateHash(['42', '99'])
        expect(a).to.equal(b)
      })
    })

    context('given two different inputs', function () {
      it('returns different hashes', async function () {
        const a = await g.generateHash(['1'])
        const b = await g.generateHash(['2'])
        expect(a).to.not.equal(b)
      })
    })

    context('given a hex-prefixed input from a prior call', function () {
      it('chain-hashes without complaint and returns hex256', async function () {
        const first = await g.generateHash(['1'])
        const chained = await g.generateHash([first])
        expect(chained).to.match(HEX_RE)
      })
    })

    context('given a non-numeric, non-hex string', function () {
      it('throws synchronously', function () {
        expect(() => g.generateHash(['not-a-field-element'])).to.throw(Error)
      })
    })
  })

  describe('generateAnchor', function () {
    context('given a valid config and exactly n secrets', function () {
      it('returns a non-empty evaluations array of hex256 strings', async function () {
        const result = await g.generateAnchor(DEFAULT_CONFIG, DEFAULT_SECRETS)
        expect(result.evaluations).to.be.an('array').that.is.not.empty
        for (const ev of result.evaluations) expect(ev).to.match(HEX_RE)
      })
    })

    context('given two secret-sets that differ', function () {
      it('produces different evaluations', async function () {
        const altSecrets = DEFAULT_SECRETS.map((s, i) => ({ ...s, sub: `alt-user-${i}` }))
        const a = await g.generateAnchor(DEFAULT_CONFIG, DEFAULT_SECRETS)
        const b = await g.generateAnchor(DEFAULT_CONFIG, altSecrets)
        expect(a.evaluations).to.not.deep.equal(b.evaluations)
      })
    })

    context('given fewer than n secrets', function () {
      it('throws synchronously (dimension mismatch)', function () {
        expect(() => g.generateAnchor(DEFAULT_CONFIG, [DEFAULT_SECRET])).to.throw(Error)
      })
    })

    context('given an empty secrets array', function () {
      it('throws synchronously', function () {
        expect(() => g.generateAnchor(DEFAULT_CONFIG, [])).to.throw(Error)
      })
    })

    context('given a null config', function () {
      it('throws synchronously', function () {
        expect(() => g.generateAnchor(null, DEFAULT_SECRETS)).to.throw(Error)
      })
    })
  })

  describe('generateAudHash', function () {
    context('given a valid config and a non-empty audience list', function () {
      it('returns audHashes plus a packed hAudList', async function () {
        const result = await g.generateAudHash(DEFAULT_CONFIG, ['my-client-id'])
        expect(result.audHashes).to.be.an('array').that.is.not.empty
        expect(result.hAudList).to.match(HEX_RE)
        for (const h of result.audHashes) expect(h).to.match(HEX_RE)
      })
    })

    context('given fewer audiences than numAudienceLimit', function () {
      it('pads audHashes up to numAudienceLimit', async function () {
        const result = await g.generateAudHash(DEFAULT_CONFIG, ['aud-1'])
        expect(result.audHashes).to.have.length(DEFAULT_CONFIG.numAudienceLimit)
      })
    })

    context('given two different audience lists', function () {
      it('produces different hAudList digests', async function () {
        const a = await g.generateAudHash(DEFAULT_CONFIG, ['client-a'])
        const b = await g.generateAudHash(DEFAULT_CONFIG, ['client-b'])
        expect(a.hAudList).to.not.equal(b.hAudList)
      })
    })

    context('given a null config', function () {
      it('throws synchronously', function () {
        expect(() => g.generateAudHash(null, ['aud-1'])).to.throw(Error)
      })
    })
  })

  describe('generateLeafHash', function () {
    context('given a valid config, issuer URL and base64 RSA modulus', function () {
      it('returns a 0x-prefixed 256-bit hex string', async function () {
        const result = await g.generateLeafHash(
          DEFAULT_CONFIG,
          DEFAULT_SECRET.iss,
          PLACEHOLDER_RSA_MODULUS_B64,
        )
        expect(result).to.match(HEX_RE)
      })

      it('is deterministic for the same inputs', async function () {
        const a = await g.generateLeafHash(
          DEFAULT_CONFIG,
          DEFAULT_SECRET.iss,
          PLACEHOLDER_RSA_MODULUS_B64,
        )
        const b = await g.generateLeafHash(
          DEFAULT_CONFIG,
          DEFAULT_SECRET.iss,
          PLACEHOLDER_RSA_MODULUS_B64,
        )
        expect(a).to.equal(b)
      })
    })

    context('given different issuer URLs', function () {
      it('produces different digests', async function () {
        const a = await g.generateLeafHash(
          DEFAULT_CONFIG,
          'https://issuer-a.example',
          PLACEHOLDER_RSA_MODULUS_B64,
        )
        const b = await g.generateLeafHash(
          DEFAULT_CONFIG,
          'https://issuer-b.example',
          PLACEHOLDER_RSA_MODULUS_B64,
        )
        expect(a).to.not.equal(b)
      })
    })

    context('given different RSA moduli', function () {
      it('produces different digests', async function () {
        const altModulus = Buffer.alloc(256, 0xbb).toString('base64')
        const a = await g.generateLeafHash(
          DEFAULT_CONFIG,
          DEFAULT_SECRET.iss,
          PLACEHOLDER_RSA_MODULUS_B64,
        )
        const b = await g.generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, altModulus)
        expect(a).to.not.equal(b)
      })
    })

    context('given an invalid base64 RSA modulus', function () {
      it('throws synchronously', function () {
        expect(() =>
          g.generateLeafHash(DEFAULT_CONFIG, DEFAULT_SECRET.iss, '!!not-base64!!'),
        ).to.throw(Error)
      })
    })

    context('given a null config', function () {
      it('throws synchronously', function () {
        expect(() => g.generateLeafHash(null, DEFAULT_SECRET.iss, PLACEHOLDER_RSA_MODULUS_B64)).to.throw(
          Error,
        )
      })
    })
  })
})
