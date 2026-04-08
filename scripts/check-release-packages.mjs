#!/usr/bin/env node

import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(__dirname, '..')

const RELEASE_PACKAGES = [
  {
    path: 'platform-packages/node-darwin-x64/package.json',
    name: '@baerae/zkap-zkp-node-darwin-x64',
  },
  {
    path: 'platform-packages/node-darwin-arm64/package.json',
    name: '@baerae/zkap-zkp-node-darwin-arm64',
  },
  {
    path: 'platform-packages/node-linux-x64-gnu/package.json',
    name: '@baerae/zkap-zkp-node-linux-x64-gnu',
  },
  {
    path: 'platform-packages/node-linux-x64-musl/package.json',
    name: '@baerae/zkap-zkp-node-linux-x64-musl',
  },
  {
    path: 'packages/sdk-node/package.json',
    name: '@baerae/zkap-zkp-node',
  },
  {
    path: 'packages/sdk-wasm/package.json',
    name: '@baerae/zkap-zkp-wasm',
  },
  {
    path: 'packages/sdk/package.json',
    name: '@baerae/zkap-zkp',
  },
]

const expectedVersion = process.argv[2]
const packages = RELEASE_PACKAGES.map(({ path, name }) => ({
  path,
  name,
  json: JSON.parse(readFileSync(resolve(rootDir, path), 'utf8')),
}))

const versions = new Set(packages.map(({ json }) => json.version))
if (versions.size !== 1) {
  console.error('Release package versions are not synchronized:')
  for (const pkg of packages) {
    console.error(`  ${pkg.name}: ${pkg.json.version} (${pkg.path})`)
  }
  process.exit(1)
}

const [version] = versions
if (expectedVersion && version !== expectedVersion) {
  console.error(`Expected release version ${expectedVersion}, found ${version}`)
  process.exit(1)
}

const sdkPkg = packages.find((pkg) => pkg.name === '@baerae/zkap-zkp')
const sdkNodePkg = packages.find((pkg) => pkg.name === '@baerae/zkap-zkp-node')
const platformPackages = packages.filter((pkg) => pkg.name.startsWith('@baerae/zkap-zkp-node-'))

if (sdkPkg.json.dependencies?.['@baerae/zkap-zkp-node'] !== version) {
  console.error(
    `packages/sdk/package.json must depend on @baerae/zkap-zkp-node@${version}, found ${sdkPkg.json.dependencies?.['@baerae/zkap-zkp-node']}`,
  )
  process.exit(1)
}

for (const platformPkg of platformPackages) {
  const depVersion = sdkNodePkg.json.optionalDependencies?.[platformPkg.name]
  if (depVersion !== version) {
    console.error(
      `packages/sdk-node/package.json must optionalDepend on ${platformPkg.name}@${version}, found ${depVersion}`,
    )
    process.exit(1)
  }
}

for (const pkg of packages) {
  if (pkg.json.publishConfig?.access !== 'public') {
    console.error(`${pkg.name} is missing publishConfig.access=public (${pkg.path})`)
    process.exit(1)
  }
}

console.log(`Release packages validated at version ${version}`)
