#!/usr/bin/env node

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(__dirname, '..')

const RELEASE_PACKAGES = [
  {
    path: 'platform-packages/node-darwin-x64/package.json',
    name: '@baerae/zkap-zkp-sdk-node-darwin-x64',
  },
  {
    path: 'platform-packages/node-darwin-arm64/package.json',
    name: '@baerae/zkap-zkp-sdk-node-darwin-arm64',
  },
  {
    path: 'platform-packages/node-linux-x64-gnu/package.json',
    name: '@baerae/zkap-zkp-sdk-node-linux-x64-gnu',
  },
  {
    path: 'platform-packages/node-linux-x64-musl/package.json',
    name: '@baerae/zkap-zkp-sdk-node-linux-x64-musl',
  },
  {
    path: 'packages/sdk-node/package.json',
    name: '@baerae/zkap-zkp-sdk-node',
  },
  {
    path: 'packages/sdk-wasm/package.json',
    name: '@baerae/zkap-zkp-sdk-wasm',
  },
  {
    path: 'packages/sdk-react-native/package.json',
    name: '@baerae/zkap-zkp-sdk-react-native',
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

function extractOptional(pattern, path) {
  const text = readFileSync(resolve(rootDir, path), 'utf8')
  const match = pattern.exec(text)
  return match?.[1]
}

function extractRequired(pattern, path, label) {
  const text = readFileSync(resolve(rootDir, path), 'utf8')
  const match = pattern.exec(text)
  if (!match) {
    console.error(`${path} is missing ${label}`)
    process.exit(1)
  }
  return match[1]
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`)
}

function gitHeadForPath(path) {
  try {
    return execFileSync('git', ['-C', resolve(rootDir, path), 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim()
  } catch {
    return null
  }
}

function checkLocalCargoPatches() {
  const configPath = resolve(rootDir, '.cargo/config.toml')
  if (!existsSync(configPath)) return

  const text = readFileSync(configPath, 'utf8')
  const patches = [...text.matchAll(/^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}]*\bpath\s*=\s*"([^"]+)"/gm)]
    .map((match) => ({
      name: match[1],
      path: match[2],
      head: gitHeadForPath(match[2]),
      releaseRev: extractOptional(
        new RegExp(`${escapeRegExp(match[1])}\\s*=\\s*\\{[^}]*\\brev\\s*=\\s*"([0-9a-f]{40})"`),
        'Cargo.toml',
      ),
    }))
    .filter((patch) => patch.name === 'zkap-service' || patch.name === 'ark-ar1cs')

  if (patches.length === 0) return

  const message = [
    'Local Cargo patches are active for release dependencies.',
    'Public npm publish would use Cargo.toml git revs, not the local patched code validated here:',
    ...patches.map((patch) => {
      const suffix =
        patch.head && patch.releaseRev && patch.head !== patch.releaseRev
          ? ` (local HEAD ${patch.head}, release rev ${patch.releaseRev})`
          : ''
      return `  - ${patch.name}: ${patch.path}${suffix}`
    }),
    'Update the release git revs before public publish, or rerun with ZKAP_ALLOW_LOCAL_PATCHES=1 for an internal local-only validation.',
  ].join('\n')

  if (process.env.ZKAP_ALLOW_LOCAL_PATCHES === '1') {
    console.warn(message)
    return
  }

  console.error(message)
  process.exit(1)
}

checkLocalCargoPatches()

const cargoZkapCircuitRev = extractRequired(
  /zkap-service\s*=\s*\{[^}]*\brev\s*=\s*"([0-9a-f]{40})"/,
  'Cargo.toml',
  'zkap-service git rev',
)
const sdkZkapCircuitRev = extractRequired(
  /ZKAP_CIRCUIT_COMMIT\s*=\s*['"]([0-9a-f]{40})['"]/,
  'packages/sdk/src/release-shared.ts',
  'ZKAP_CIRCUIT_COMMIT',
)
const nodeZkapCircuitRev = extractRequired(
  /const ZKAP_CIRCUIT_COMMIT:\s*&str\s*=\s*"([0-9a-f]{40})";/,
  'packages/sdk-node/src/lib.rs',
  'ZKAP_CIRCUIT_COMMIT',
)

if (sdkZkapCircuitRev !== cargoZkapCircuitRev || nodeZkapCircuitRev !== cargoZkapCircuitRev) {
  console.error('zkap-circuit compatibility pins are not synchronized:')
  console.error(`  Cargo.toml zkap-service rev: ${cargoZkapCircuitRev}`)
  console.error(`  packages/sdk/src/release-shared.ts: ${sdkZkapCircuitRev}`)
  console.error(`  packages/sdk-node/src/lib.rs: ${nodeZkapCircuitRev}`)
  process.exit(1)
}

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
const sdkNodePkg = packages.find((pkg) => pkg.name === '@baerae/zkap-zkp-sdk-node')
const sdkWasmPkg = packages.find((pkg) => pkg.name === '@baerae/zkap-zkp-sdk-wasm')
const sdkReactNativePkg = packages.find((pkg) => pkg.name === '@baerae/zkap-zkp-sdk-react-native')
const platformPackages = packages.filter((pkg) => pkg.name.startsWith('@baerae/zkap-zkp-sdk-node-'))
const platformPackageNames = new Set(platformPackages.map((pkg) => pkg.name))
const platformTargets = new Set([
  'x86_64-apple-darwin',
  'aarch64-apple-darwin',
  'x86_64-unknown-linux-gnu',
  'x86_64-unknown-linux-musl',
])

for (const depPkg of [sdkNodePkg, sdkWasmPkg, sdkReactNativePkg]) {
  const depVersion = sdkPkg.json.peerDependencies?.[depPkg.name]
  if (depVersion !== version) {
    console.error(
      `packages/sdk/package.json must peerDepend on ${depPkg.name}@${version}, found ${depVersion}`,
    )
    process.exit(1)
  }
  if (sdkPkg.json.dependencies?.[depPkg.name]) {
    console.error(
      `packages/sdk/package.json must not hard-depend on ${depPkg.name}; runtime SDK packages must stay optional`,
    )
    process.exit(1)
  }
  if (sdkPkg.json.peerDependenciesMeta?.[depPkg.name]?.optional !== true) {
    console.error(
      `packages/sdk/package.json must mark peer ${depPkg.name} optional`,
    )
    process.exit(1)
  }
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

for (const depName of Object.keys(sdkNodePkg.json.optionalDependencies ?? {})) {
  if (depName.startsWith('@baerae/zkap-zkp-sdk-node-') && !platformPackageNames.has(depName)) {
    console.error(`packages/sdk-node/package.json has unexpected platform optionalDependency ${depName}`)
    process.exit(1)
  }
}

for (const target of platformTargets) {
  if (!sdkNodePkg.json.napi?.targets?.includes(target)) {
    console.error(`packages/sdk-node/package.json napi.targets is missing ${target}`)
    process.exit(1)
  }
}

for (const target of sdkNodePkg.json.napi?.targets ?? []) {
  if (!platformTargets.has(target)) {
    console.error(`packages/sdk-node/package.json has unexpected napi target ${target}`)
    process.exit(1)
  }
}

for (const file of sdkNodePkg.json.files ?? []) {
  if (file.endsWith('.node') || file.includes('*.node')) {
    console.error(
      `packages/sdk-node/package.json must not publish native binaries from the wrapper package (${file})`,
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
