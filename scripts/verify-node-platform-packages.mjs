#!/usr/bin/env node

import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(scriptDir, '..')
const platformRoot = join(rootDir, 'platform-packages')

const PACKAGES = [
  ['node-darwin-x64', '@baerae/zkap-zkp-sdk-node-darwin-x64', 'index.darwin-x64.node'],
  ['node-darwin-arm64', '@baerae/zkap-zkp-sdk-node-darwin-arm64', 'index.darwin-arm64.node'],
  ['node-linux-x64-gnu', '@baerae/zkap-zkp-sdk-node-linux-x64-gnu', 'index.linux-x64-gnu.node'],
  ['node-linux-x64-musl', '@baerae/zkap-zkp-sdk-node-linux-x64-musl', 'index.linux-x64-musl.node'],
]

const cwd = resolve(process.cwd())
const selected = PACKAGES.filter(([dir]) => resolve(platformRoot, dir) === cwd)
const targets = selected.length > 0 ? selected : PACKAGES
const errors = []

for (const [dir, expectedName, expectedBinary] of targets) {
  const packageDir = join(platformRoot, dir)
  const packageJsonPath = join(packageDir, 'package.json')
  let packageJson

  try {
    packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
  } catch (error) {
    errors.push(`${dir}: cannot read package.json: ${error.message}`)
    continue
  }

  if (packageJson.name !== expectedName) {
    errors.push(`${dir}: expected package name ${expectedName}, found ${packageJson.name}`)
  }

  if (packageJson.main !== expectedBinary) {
    errors.push(`${dir}: expected main ${expectedBinary}, found ${packageJson.main}`)
  }

  if (!Array.isArray(packageJson.files) || !packageJson.files.includes(expectedBinary)) {
    errors.push(`${dir}: files must include ${expectedBinary}`)
  }

  const binaryPath = join(packageDir, expectedBinary)
  if (!existsSync(binaryPath)) {
    errors.push(`${dir}: missing ${expectedBinary}`)
    continue
  }

  const stat = statSync(binaryPath)
  if (!stat.isFile()) {
    errors.push(`${dir}: ${expectedBinary} is not a file`)
    continue
  }

  if (stat.size <= 0) {
    errors.push(`${dir}: ${expectedBinary} is empty`)
    continue
  }

  console.log(`${dir}: found ${expectedBinary} (${stat.size} bytes)`)
}

if (errors.length > 0) {
  console.error('Node platform package verification failed:')
  for (const error of errors) {
    console.error(`  - ${error}`)
  }
  process.exit(1)
}
