#!/usr/bin/env node

/**
 * Generate the React Native UniFFI bindings into packages/sdk-react-native.
 *
 * The TypeScript/C++ bindings embed FFI checksums that MUST match the compiled
 * `zkap-uniffi-bindings` native library. They are NOT committed (see the repo
 * .gitignore): they are regenerated from the Rust crate here, at `prepack` time
 * for every publish, so they can never drift from the native interface.
 *
 * They drifted once while committed: the Rust `prove` interface changed (P2
 * zkap-service façade) but the committed bindings were never regenerated, so the
 * published 0.1.6 TS expected checksum 35511 while the shipped xcframework
 * returned 59563 — breaking every on-device `prove()` with an "incompatible
 * Uniffi versions" error.
 *
 * The generator (`uniffi-bindgen-react-native`) must run from the crate
 * directory: its `--library` path still triggers a `cargo metadata
 * --manifest-path Cargo.toml` resolved against the cwd, which fails in the
 * package directory (no Cargo.toml there). The old inline `generate:ubrn` npm
 * script ran it from the package dir and therefore never actually worked.
 *
 * Flags:
 *   --no-build   Reuse an existing target/debug dylib instead of `cargo build`.
 */

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(__dirname, '..')
const crateDir = join(rootDir, 'crates/uniffi-bindings')
const rnDir = join(rootDir, 'packages/sdk-react-native')
const tsDir = join(rnDir, 'src/generated')
const cppDir = join(rnDir, 'cpp/generated')
const ubrnBin = join(rootDir, 'node_modules/.bin/uniffi-bindgen-react-native')
const CRATE = 'zkap_uniffi_bindings'

const skipBuild = process.argv.includes('--no-build')

function run(cmd, args, opts = {}) {
  execFileSync(cmd, args, { stdio: 'inherit', ...opts })
}

function dylibPath() {
  const base = join(rootDir, 'target/debug/libzkap_uniffi_bindings')
  for (const ext of ['.dylib', '.so', '.dll']) {
    if (existsSync(base + ext)) return base + ext
  }
  throw new Error(
    'built zkap-uniffi-bindings library not found under target/debug — run without --no-build',
  )
}

if (!skipBuild) {
  run('cargo', ['build', '-p', 'zkap-uniffi-bindings'], { cwd: rootDir })
}

mkdirSync(tsDir, { recursive: true })
mkdirSync(cppDir, { recursive: true })

// ubrn must run from the crate directory (cargo metadata resolves Cargo.toml
// against the cwd). Output paths are absolute so they land in the RN package.
run(
  ubrnBin,
  [
    'generate', 'jsi', 'bindings',
    '--library', '--crate', CRATE,
    '--ts-dir', tsDir,
    '--cpp-dir', cppDir,
    dylibPath(),
  ],
  { cwd: crateDir },
)

// Format if the tools are available. ubrn already attempts prettier/clang-format
// and warns when missing; missing formatters are non-fatal (the bindings are
// generated, just unformatted), so we do not fail the build on their absence.
console.log('React Native UniFFI bindings generated into packages/sdk-react-native.')
