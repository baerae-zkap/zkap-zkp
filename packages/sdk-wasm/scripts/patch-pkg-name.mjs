#!/usr/bin/env node
// Keeps the wasm-pack generated package metadata aligned with the package root.

import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const outDir = process.argv[2] ?? 'pkg'
const rootPkgJsonPath = resolve(import.meta.dirname, '..', 'package.json')
const pkgJsonPath = resolve(import.meta.dirname, '..', outDir, 'package.json')
const pkgGitignorePath = resolve(import.meta.dirname, '..', outDir, '.gitignore')

const rootPkg = JSON.parse(readFileSync(rootPkgJsonPath, 'utf8'))
const pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8'))
pkg.name = rootPkg.name
pkg.version = rootPkg.version
pkg.license = rootPkg.license
pkg.repository = rootPkg.repository
pkg.sideEffects = rootPkg.sideEffects
writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + '\n')
rmSync(pkgGitignorePath, { force: true })
console.log(`Patched ${pkgJsonPath}: aligned metadata with ${rootPkgJsonPath}`)
