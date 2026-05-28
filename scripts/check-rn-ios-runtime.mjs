#!/usr/bin/env node

import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const targets =
  process.argv.slice(2).length > 0
    ? process.argv.slice(2)
    : ['aarch64-apple-ios', 'aarch64-apple-ios-sim', 'x86_64-apple-ios']

for (const target of targets) {
  let tree
  try {
    tree = execFileSync(
      'cargo',
      ['tree', '-p', 'zkap-uniffi-bindings', '--target', target],
      { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    )
  } catch (error) {
    const stderr = error.stderr?.toString() ?? ''
    throw new Error(`cargo tree failed for ${target}\n${stderr}`)
  }

  const forbidden = tree.match(/\b(wasmtime|cranelift|pulley|wasmi)\b/i)
  if (forbidden) {
    throw new Error(
      `React Native iOS runtime check failed for ${target}: unexpected ${forbidden[1]} dependency`,
    )
  }

  console.log(
    `React Native iOS wasm runtime validated for ${target}: no native wasm runtime dependency`,
  )
}
