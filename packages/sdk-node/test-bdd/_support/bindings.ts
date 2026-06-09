/**
 * Shared lazy-import + skip helpers for the mocha BDD suite.
 *
 * Mirrors the binary-missing guard used by `__test__/*.spec.ts` so
 * environments without a built native binary skip every suite cleanly
 * instead of crashing on require.
 */

import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

export const PACKAGE_ROOT = resolve(import.meta.dirname ?? __dirname, '..', '..')
export const INDEX_JS = resolve(PACKAGE_ROOT, 'index.js')
export const binaryMissing = !existsSync(INDEX_JS)

let cachedBindings: Record<string, unknown> | null = null

/**
 * Lazily load the napi binding. Throws if the binary is missing — but
 * `skipIfBindingMissing` (below) prevents callers from getting here in
 * that case.
 */
export async function loadBindings(): Promise<Record<string, unknown>> {
  if (cachedBindings) return cachedBindings
  cachedBindings = (await import(INDEX_JS)) as Record<string, unknown>
  return cachedBindings
}

/**
 * Mocha `before` hook that skips the enclosing suite when the native
 * binary has not been built yet. Use as:
 *
 *   describe('...', function () {
 *     before(skipIfBindingMissing(this))
 *     ...
 *   })
 *
 * `this` (typed as `Mocha.Suite`) lets the helper call `this.skip()`
 * directly instead of every test reaching for the suite reference.
 */
export function skipIfBindingMissing(suite: Mocha.Suite | Mocha.Context) {
  return function () {
    if (binaryMissing) {
      console.warn(`[mocha-bdd] Native binary not found at ${INDEX_JS}; suite skipped.`)
      suite.skip()
    }
  }
}
