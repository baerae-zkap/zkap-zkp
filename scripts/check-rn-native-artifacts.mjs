#!/usr/bin/env node

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(__dirname, '..')
const rnDir = join(rootDir, 'packages/sdk-react-native')

const errors = []
const warnings = []

const rnPackage = JSON.parse(readFileSync(join(rnDir, 'package.json'), 'utf8'))
const packageFiles = new Set(
  (rnPackage.files ?? []).map((entry) => normalizePackagePath(entry)),
)

function normalizePackagePath(path) {
  return path.replaceAll('\\', '/').replace(/^\.\//, '')
}

function rel(path) {
  return relative(rootDir, path).replaceAll('\\', '/')
}

function packageFilesCover(path) {
  const normalized = normalizePackagePath(path)
  for (const entry of packageFiles) {
    if (entry.endsWith('/') && normalized.startsWith(entry)) return true
    if (entry === normalized) return true
  }
  return false
}

function checkPackagedPath(path) {
  if (!packageFilesCover(path)) {
    errors.push(`packages/sdk-react-native/package.json files does not include ${path}`)
  }
}

function checkFile(path) {
  const absolute = join(rnDir, path)
  if (!existsSync(absolute)) {
    errors.push(`missing React Native native artifact: ${rel(absolute)}`)
    return null
  }

  const stat = statSync(absolute)
  if (!stat.isFile()) {
    errors.push(`React Native native artifact is not a file: ${rel(absolute)}`)
    return null
  }

  if (stat.size <= 0) {
    errors.push(`React Native native artifact is empty: ${rel(absolute)}`)
    return null
  }

  return { path, absolute, stat }
}

function parseAndroidTargets() {
  const text = readFileSync(join(rnDir, 'ubrn.config.yaml'), 'utf8')
  const targets = []
  let inAndroid = false
  let inTargets = false

  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inAndroid = line.trim() === 'android:'
      inTargets = false
      continue
    }

    if (!inAndroid) continue

    if (/^\s{2}targets:\s*$/.test(line)) {
      inTargets = true
      continue
    }

    if (inTargets) {
      const match = /^\s{4}-\s+([A-Za-z0-9_-]+)\s*$/.exec(line)
      if (match) {
        targets.push(match[1])
      } else if (/^\s{2}\S/.test(line)) {
        inTargets = false
      }
    }
  }

  if (targets.length === 0) {
    errors.push('packages/sdk-react-native/ubrn.config.yaml has no android.targets')
  }

  return targets
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function collectTrackedSourceFiles() {
  const output = execFileSync(
    'git',
    [
      'ls-files',
      'Cargo.toml',
      'Cargo.lock',
      'crates/prover',
      'crates/uniffi-bindings',
      'packages/sdk-react-native/ios/include',
      'packages/sdk-react-native/ios/uniffi',
    ],
    {
      cwd: rootDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )

  return output
    .split(/\r?\n/)
    .filter(Boolean)
    .map((path) => join(rootDir, path))
    .filter((path) => existsSync(path))
}

function newestFile(files) {
  return files
    .map((path) => ({ path, stat: statSync(path) }))
    .sort((left, right) => right.stat.mtimeMs - left.stat.mtimeMs)[0]
}

function oldestFile(files) {
  return files
    .map((path) => ({ path, stat: statSync(path) }))
    .sort((left, right) => left.stat.mtimeMs - right.stat.mtimeMs)[0]
}

function checkFreshness(label, artifacts) {
  if (process.env.ZKAP_SKIP_NATIVE_FRESHNESS === '1') {
    warnings.push(`${label}: skipped freshness check via ZKAP_SKIP_NATIVE_FRESHNESS=1`)
    return
  }

  const sourceFiles = collectTrackedSourceFiles()
  const newestSource = newestFile(sourceFiles)
  const oldestArtifact = oldestFile(artifacts.map((artifact) => artifact.absolute))
  const toleranceMs = 1000

  if (oldestArtifact.stat.mtimeMs + toleranceMs < newestSource.stat.mtimeMs) {
    errors.push(
      `${label} native artifacts look stale: newest source ${rel(newestSource.path)} ` +
        `is newer than oldest artifact ${rel(oldestArtifact.path)}. ` +
        'Rebuild with scripts/rebuild-uniffi-react-native.sh before packing.',
    )
  }
}

const androidTargets = parseAndroidTargets()
const expectedAndroidArtifacts = androidTargets.map(
  (abi) => `android/libs/${abi}/libzkap_uniffi_bindings.so`,
)
const listedAndroidArtifacts = [...packageFiles]
  .filter((path) => path.startsWith('android/libs/') && path.endsWith('.so'))
  .sort()

for (const path of expectedAndroidArtifacts) {
  checkPackagedPath(path)
}

for (const path of listedAndroidArtifacts) {
  if (!expectedAndroidArtifacts.includes(path)) {
    errors.push(`package.json files includes unexpected Android native artifact ${path}`)
  }
}

const androidArtifacts = expectedAndroidArtifacts.map(checkFile).filter(Boolean)

const xcframeworkDir = join(rnDir, 'ios/ZkapZkp.xcframework')
checkPackagedPath('ios/ZkapZkp.xcframework/Info.plist')

const expectedIosArtifacts = [
  'ios/ZkapZkp.xcframework/Info.plist',
  'ios/ZkapZkp.xcframework/ios-arm64/Headers/zkap_uniffi_bindingsFFI.h',
  'ios/ZkapZkp.xcframework/ios-arm64/libzkap_uniffi_bindings.a',
  'ios/ZkapZkp.xcframework/ios-arm64_x86_64-simulator/Headers/zkap_uniffi_bindingsFFI.h',
  'ios/ZkapZkp.xcframework/ios-arm64_x86_64-simulator/libzkap_uniffi_bindings.a',
]

if (!existsSync(xcframeworkDir)) {
  errors.push(`missing React Native iOS XCFramework: ${rel(xcframeworkDir)}`)
}

const iosArtifacts = expectedIosArtifacts.map(checkFile).filter(Boolean)
const canonicalHeader = join(rnDir, 'ios/include/zkap_uniffi_bindingsFFI.h')

if (existsSync(canonicalHeader)) {
  const expectedHeaderHash = sha256(canonicalHeader)
  for (const artifact of iosArtifacts.filter((item) => item.path.endsWith('.h'))) {
    if (sha256(artifact.absolute) !== expectedHeaderHash) {
      errors.push(
        `${rel(artifact.absolute)} does not match ${rel(canonicalHeader)}; rebuild the XCFramework`,
      )
    }
  }
}

if (existsSync(join(rnDir, 'android/libs'))) {
  for (const abi of readdirSync(join(rnDir, 'android/libs'))) {
    const abiDir = join(rnDir, 'android/libs', abi)
    if (!statSync(abiDir).isDirectory()) continue
    for (const file of readdirSync(abiDir)) {
      if (!file.endsWith('.so')) continue
      const artifactPath = `android/libs/${abi}/${file}`
      if (!expectedAndroidArtifacts.includes(artifactPath)) {
        warnings.push(`${artifactPath} exists locally but is not included in the npm package`)
      }
    }
  }
}

if (androidArtifacts.length === expectedAndroidArtifacts.length) {
  checkFreshness('Android', androidArtifacts)
}

if (iosArtifacts.length === expectedIosArtifacts.length) {
  checkFreshness(
    'iOS',
    iosArtifacts.filter((artifact) => artifact.path.endsWith('.a')),
  )
}

// Generated UniFFI bindings are not committed (see .gitignore); they are produced
// by `generate:ubrn` at prepack time. Fail loudly if a publish would ship without
// them — a binding/native checksum mismatch is exactly the 0.1.6 on-device break.
const generatedBindings = [
  'src/generated/zkap_uniffi_bindings.ts',
  'src/generated/zkap_uniffi_bindings-ffi.ts',
  'cpp/generated/zkap_uniffi_bindings.cpp',
  'cpp/generated/zkap_uniffi_bindings.hpp',
]
const generatedArtifacts = []
for (const path of generatedBindings) {
  checkPackagedPath(path)
  const artifact = checkFile(path)
  if (artifact) generatedArtifacts.push(artifact)
}

for (const warning of warnings) {
  console.warn(`WARN: ${warning}`)
}

if (errors.length > 0) {
  console.error('React Native native artifact verification failed:')
  for (const error of errors) {
    console.error(`  - ${error}`)
  }
  process.exit(1)
}

for (const artifact of [...androidArtifacts, ...iosArtifacts, ...generatedArtifacts]) {
  console.log(`${rel(artifact.absolute)} (${artifact.stat.size} bytes)`)
}
console.log('React Native native artifacts validated')
