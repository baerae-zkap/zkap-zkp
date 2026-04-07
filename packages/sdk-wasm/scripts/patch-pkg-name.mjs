#!/usr/bin/env node
// Patches the wasm-pack generated package.json to use the scoped npm name.
// wasm-pack derives the name from the Cargo crate name (zkap-zkp-wasm),
// but we publish as @baerae/zkap-zkp-wasm.

import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const outDir = process.argv[2] ?? 'pkg'
const pkgJsonPath = resolve(import.meta.dirname, '..', outDir, 'package.json')

const pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8'))
pkg.name = '@baerae/zkap-zkp-wasm'
writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + '\n')
console.log(`Patched ${pkgJsonPath}: name → ${pkg.name}`)
