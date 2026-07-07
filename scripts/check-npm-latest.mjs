#!/usr/bin/env node

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(__dirname, '..')

const RELEASE_PACKAGE_PATHS = [
  'platform-packages/node-darwin-x64/package.json',
  'platform-packages/node-darwin-arm64/package.json',
  'platform-packages/node-linux-x64-gnu/package.json',
  'platform-packages/node-linux-x64-musl/package.json',
  'platform-packages/node-linux-arm64-gnu/package.json',
  'platform-packages/node-linux-arm64-musl/package.json',
  'packages/sdk-node/package.json',
  'packages/sdk-wasm/package.json',
  'packages/sdk-react-native/package.json',
  'packages/sdk/package.json',
]

function parseSemver(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(value)
  if (!match) {
    throw new Error(`Invalid semver: ${value}`)
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
  }
}

function compareIdentifiers(left, right) {
  const leftIsNumeric = /^\d+$/.test(left)
  const rightIsNumeric = /^\d+$/.test(right)

  if (leftIsNumeric && rightIsNumeric) {
    return Number(left) - Number(right)
  }

  if (leftIsNumeric) return -1
  if (rightIsNumeric) return 1
  return left.localeCompare(right)
}

function compareSemver(left, right) {
  const a = parseSemver(left)
  const b = parseSemver(right)

  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) {
      return a[key] - b[key]
    }
  }

  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0
  if (a.prerelease.length === 0) return 1
  if (b.prerelease.length === 0) return -1

  const maxLength = Math.max(a.prerelease.length, b.prerelease.length)
  for (let index = 0; index < maxLength; index += 1) {
    const leftId = a.prerelease[index]
    const rightId = b.prerelease[index]
    if (leftId === undefined) return -1
    if (rightId === undefined) return 1
    const diff = compareIdentifiers(leftId, rightId)
    if (diff !== 0) return diff
  }

  return 0
}

function loadPackage(path) {
  return JSON.parse(readFileSync(resolve(rootDir, path), 'utf8'))
}

for (const packagePath of RELEASE_PACKAGE_PATHS) {
  const pkg = loadPackage(packagePath)
  const version = pkg.version

  let latest = ''
  try {
    latest = execFileSync(
      'npm',
      ['view', pkg.name, 'dist-tags.latest', '--registry', 'https://registry.npmjs.org'],
      {
        cwd: rootDir,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ).trim()
  } catch (error) {
    latest = ''
  }

  if (!latest) {
    console.log(`${pkg.name}: no published version found, treating as first publish`)
    continue
  }

  if (compareSemver(version, latest) <= 0) {
    console.error(`${pkg.name}: target version ${version} is not newer than latest ${latest}`)
    process.exit(1)
  }

  console.log(`${pkg.name}: ${version} > ${latest}`)
}
