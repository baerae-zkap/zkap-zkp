#!/usr/bin/env node

import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const rootDir = resolve(scriptDir, '..')
const tmpRoot = mkdtempSync(join(tmpdir(), 'zkap-zkp-consumer-smoke-'))
const packDir = join(tmpRoot, 'packs')
const npmCacheDir = join(tmpRoot, 'npm-cache')
const npmLogsDir = join(tmpRoot, 'npm-logs')

mkdirSync(packDir, { recursive: true })

const PLATFORM_PACKAGES = [
  {
    dir: 'platform-packages/node-darwin-x64',
    name: '@baerae/zkap-zkp-node-darwin-x64',
    binary: 'index.darwin-x64.node',
    os: 'darwin',
    cpu: 'x64',
  },
  {
    dir: 'platform-packages/node-darwin-arm64',
    name: '@baerae/zkap-zkp-node-darwin-arm64',
    binary: 'index.darwin-arm64.node',
    os: 'darwin',
    cpu: 'arm64',
  },
  {
    dir: 'platform-packages/node-linux-x64-gnu',
    name: '@baerae/zkap-zkp-node-linux-x64-gnu',
    binary: 'index.linux-x64-gnu.node',
    os: 'linux',
    cpu: 'x64',
    libc: 'glibc',
  },
  {
    dir: 'platform-packages/node-linux-x64-musl',
    name: '@baerae/zkap-zkp-node-linux-x64-musl',
    binary: 'index.linux-x64-musl.node',
    os: 'linux',
    cpu: 'x64',
    libc: 'musl',
  },
]

function npmEnv() {
  return {
    ...process.env,
    npm_config_cache: npmCacheDir,
    npm_config_logs_dir: npmLogsDir,
    npm_config_prefer_offline: 'true',
  }
}

function quoteArg(value) {
  return /\s/.test(value) ? JSON.stringify(value) : value
}

function run(command, args, options = {}) {
  console.log(`$ ${[command, ...args].map(quoteArg).join(' ')}`)
  execFileSync(command, args, {
    cwd: options.cwd ?? rootDir,
    env: options.env ?? npmEnv(),
    stdio: 'inherit',
  })
}

function capture(command, args, options = {}) {
  console.log(`$ ${[command, ...args].map(quoteArg).join(' ')}`)
  return execFileSync(command, args, {
    cwd: options.cwd ?? rootDir,
    env: options.env ?? npmEnv(),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  })
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`)
}

function parseJsonArrayFromTail(output, label) {
  for (let index = output.lastIndexOf('['); index >= 0; index = output.lastIndexOf('[', index - 1)) {
    try {
      const parsed = JSON.parse(output.slice(index))
      if (Array.isArray(parsed)) return parsed
    } catch {
      // Keep scanning; npm lifecycle output can precede the JSON payload.
    }
  }
  throw new Error(`Could not parse JSON output from ${label}`)
}

function packPackage(packageDir) {
  const absolutePackageDir = resolve(rootDir, packageDir)
  const output = capture('npm', [
    'pack',
    '--json',
    '--pack-destination',
    packDir,
    absolutePackageDir,
  ])
  const [packed] = parseJsonArrayFromTail(output, `npm pack ${packageDir}`)
  if (!packed) {
    throw new Error(`npm pack ${packageDir} did not report a package`)
  }

  const candidate = resolve(packDir, packed.filename)
  const tarball = existsSync(candidate) ? candidate : resolve(rootDir, packed.filename)
  if (!existsSync(tarball)) {
    throw new Error(`npm pack ${packageDir} reported missing tarball ${tarball}`)
  }

  console.log(
    `packed ${packed.name}@${packed.version} from ${packageDir} (${relative(rootDir, tarball)})`,
  )
  return {
    name: packed.name,
    version: packed.version,
    tarball,
  }
}

function readPackedPackageJson(pkg) {
  const json = capture('tar', ['-xOf', pkg.tarball, 'package/package.json'])
  return JSON.parse(json)
}

function assertPackedInternalVersions(packedPackages) {
  console.log('\n== Packed internal dependency versions ==')
  const packedByName = new Map(packedPackages.map((pkg) => [pkg.name, pkg]))
  const releaseVersions = new Set(packedPackages.map((pkg) => pkg.version))
  if (releaseVersions.size !== 1) {
    throw new Error(
      `Packed packages do not share one version: ${[...releaseVersions].join(', ')}`,
    )
  }
  const [releaseVersion] = releaseVersions

  for (const pkg of packedPackages) {
    const packageJson = readPackedPackageJson(pkg)
    for (const field of ['dependencies', 'optionalDependencies']) {
      for (const [depName, depVersion] of Object.entries(packageJson[field] ?? {})) {
        if (!depName.startsWith('@baerae/zkap-zkp')) continue
        if (depVersion !== releaseVersion) {
          throw new Error(
            `${pkg.name} ${field}.${depName} must be ${releaseVersion}, found ${depVersion}`,
          )
        }
        if (packedByName.has(depName)) {
          console.log(`${pkg.name} ${field}.${depName} -> ${depVersion}`)
        }
      }
    }
  }
  console.log(`Packed internal dependency versions OK (${releaseVersion})`)
}

function isMuslRuntime() {
  if (process.platform !== 'linux') return false
  const report = process.report?.getReport?.()
  return !report?.header?.glibcVersionRuntime
}

function expectedRuntimePlatformPackage() {
  if (process.platform === 'darwin' && process.arch === 'arm64') {
    return PLATFORM_PACKAGES.find((pkg) => pkg.name === '@baerae/zkap-zkp-node-darwin-arm64')
  }
  if (process.platform === 'darwin' && process.arch === 'x64') {
    return PLATFORM_PACKAGES.find((pkg) => pkg.name === '@baerae/zkap-zkp-node-darwin-x64')
  }
  if (process.platform === 'linux' && process.arch === 'x64') {
    return PLATFORM_PACKAGES.find((pkg) =>
      isMuslRuntime()
        ? pkg.name === '@baerae/zkap-zkp-node-linux-x64-musl'
        : pkg.name === '@baerae/zkap-zkp-node-linux-x64-gnu',
    )
  }
  return undefined
}

function hasBinary(pkg) {
  return existsSync(resolve(rootDir, pkg.dir, pkg.binary))
}

function installablePlatformPackages() {
  return PLATFORM_PACKAGES.filter(
    (pkg) => pkg.os === process.platform && pkg.cpu === process.arch && hasBinary(pkg),
  )
}

function consumerPackedPackages(packedPackages) {
  const platformPackageNames = new Set(PLATFORM_PACKAGES.map((pkg) => pkg.name))
  const expectedPlatformPackage = expectedRuntimePlatformPackage()
  return packedPackages.filter(
    (pkg) => !platformPackageNames.has(pkg.name) || pkg.name === expectedPlatformPackage?.name,
  )
}

function dependencySpecs(packedPackages) {
  return Object.fromEntries(
    consumerPackedPackages(packedPackages).map((pkg) => [pkg.name, pathToFileURL(pkg.tarball).href]),
  )
}

function dependencyOverrides(packedPackages) {
  // Simulate a post-publish registry where same-version sibling packages exist.
  // assertPackedInternalVersions() keeps these overrides from hiding version drift.
  return Object.fromEntries(packedPackages.map((pkg) => [pkg.name, `$${pkg.name}`]))
}

function assertTarballContents(tarball, requiredEntries, forbiddenPrefixes) {
  const output = capture('tar', ['-tf', tarball])
  const entries = output.split('\n').filter(Boolean)
  const entrySet = new Set(entries)

  for (const entry of requiredEntries) {
    if (!entrySet.has(entry)) {
      throw new Error(`${relative(rootDir, tarball)} is missing ${entry}`)
    }
  }

  for (const prefix of forbiddenPrefixes) {
    const found = entries.find((entry) => entry.startsWith(prefix))
    if (found) {
      throw new Error(`${relative(rootDir, tarball)} unexpectedly includes ${found}`)
    }
  }
}

function smokeReactNativeTarball(rnPackage) {
  console.log('\n== React Native tarball contents ==')
  assertTarballContents(
    rnPackage.tarball,
    [
      'package/src/index.ts',
      'package/src/generated/zkap_uniffi_bindings.ts',
      'package/src/generated/zkap_uniffi_bindings-ffi.ts',
      'package/android/libs/arm64-v8a/libzkap_uniffi_bindings.so',
      'package/android/libs/x86_64/libzkap_uniffi_bindings.so',
      'package/ios/ZkapZkp.xcframework/Info.plist',
      'package/ios/ZkapZkp.xcframework/ios-arm64/libzkap_uniffi_bindings.a',
      'package/ios/ZkapZkp.xcframework/ios-arm64_x86_64-simulator/libzkap_uniffi_bindings.a',
    ],
    [
      'package/android/libs/armeabi-v7a/',
      'package/android/libs/arm64-v8a/libzkap_service.so',
      'package/android/libs/x86_64/libzkap_service.so',
    ],
  )
  console.log('React Native tarball contents OK')
}

function smokeNodeConsumer(packedPackages) {
  console.log('\n== Node/TypeScript packed consumer ==')
  const consumerDir = join(tmpRoot, 'node-consumer')
  const srcDir = join(consumerDir, 'src')
  mkdirSync(srcDir, { recursive: true })

  writeJson(join(consumerDir, 'package.json'), {
    name: 'zkap-zkp-packed-node-consumer',
    private: true,
    type: 'module',
    dependencies: dependencySpecs(packedPackages),
    overrides: dependencyOverrides(packedPackages),
  })

  run('npm', [
    'install',
    '--no-audit',
    '--no-fund',
    '--omit=optional',
    '--omit=peer',
    '--package-lock=false',
    '--fetch-retries=0',
  ], { cwd: consumerDir })

  writeJson(join(consumerDir, 'tsconfig.json'), {
    compilerOptions: {
      target: 'ES2022',
      module: 'NodeNext',
      moduleResolution: 'NodeNext',
      strict: true,
      noEmit: true,
      lib: ['ES2022', 'DOM'],
    },
    include: ['src/**/*.ts'],
  })

  writeFileSync(
    join(srcDir, 'index.ts'),
    `import { generateHash, initZkap, normalizeCircuitConfig, type CircuitConfig } from '@baerae/zkap-zkp'\n` +
      `import { generateHash as generateNodeHash } from '@baerae/zkap-zkp/node'\n` +
      `import { generateHash as generateNodeSyncHash } from '@baerae/zkap-zkp/node-sync'\n` +
      `import { generateHash as generateWasmHash, initZkap as initWasmZkap } from '@baerae/zkap-zkp/wasm'\n` +
      `import initRawWasm, { generateHash as generateRawWasmHash, type InitOutput } from '@baerae/zkap-zkp-wasm'\n\n` +
      `const config: CircuitConfig = normalizeCircuitConfig({\n` +
      `  max_jwt_b64_len: 1024,\n` +
      `  max_payload_b64_len: 640,\n` +
      `  max_aud_len: 155,\n` +
      `  max_exp_len: 20,\n` +
      `  max_iss_len: 93,\n` +
      `  max_nonce_len: 93,\n` +
      `  max_sub_len: 93,\n` +
      `  n: 6,\n` +
      `  k: 3,\n` +
      `  tree_height: 4,\n` +
      `  num_audience_limit: 5,\n` +
      `  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],\n` +
      `  forbidden_string: 'forbidden',\n` +
      `})\n\n` +
      `const rootHash: Promise<string> = generateHash(['1'])\n` +
      `const nodeHash: Promise<string> = generateNodeHash(['1'])\n` +
      `const nodeSyncHash: string = generateNodeSyncHash(['1'])\n` +
      `const wasmHash: Promise<string> = generateWasmHash(['1'])\n` +
      `const rawWasmHash: string = generateRawWasmHash(['1'])\n\n` +
      `async function smoke(): Promise<InitOutput | void> {\n` +
      `  await initZkap()\n` +
      `  await initWasmZkap()\n` +
      `  return initRawWasm()\n` +
      `}\n\n` +
      `void config\n` +
      `void rootHash\n` +
      `void nodeHash\n` +
      `void nodeSyncHash\n` +
      `void wasmHash\n` +
      `void rawWasmHash\n` +
      `void smoke\n`,
  )

  const tscBin = resolve(rootDir, 'node_modules/typescript/bin/tsc')
  if (!existsSync(tscBin)) {
    throw new Error('TypeScript is not installed. Run npm ci before packed consumer smoke.')
  }
  run(process.execPath, [tscBin, '-p', 'tsconfig.json'], { cwd: consumerDir })

  writeFileSync(
    join(consumerDir, 'cjs-smoke.cjs'),
    `const { generateHash } = require('@baerae/zkap-zkp')\n` +
      `const { generateHash: generateHashSync } = require('@baerae/zkap-zkp/node-sync')\n\n` +
      `function assertHash(label, value) {\n` +
      `  if (!/^0x[0-9a-f]{64}$/i.test(value)) {\n` +
      `    throw new Error(label + ' returned unexpected hash output: ' + value)\n` +
      `  }\n` +
      `}\n\n` +
      `(async () => {\n` +
      `  assertHash('root CJS', await generateHash(['1']))\n` +
      `  assertHash('node-sync CJS', generateHashSync(['1']))\n` +
      `  console.log('Node CJS smoke OK')\n` +
      `})().catch((error) => {\n` +
      `  console.error(error)\n` +
      `  process.exit(1)\n` +
      `})\n`,
  )
  run('node', ['cjs-smoke.cjs'], { cwd: consumerDir })

  writeFileSync(
    join(consumerDir, 'esm-smoke.mjs'),
    `import { generateHash, initZkap } from '@baerae/zkap-zkp'\n` +
      `import { generateHash as generateNodeHash } from '@baerae/zkap-zkp/node'\n\n` +
      `function assertHash(label, value) {\n` +
      `  if (!/^0x[0-9a-f]{64}$/i.test(value)) {\n` +
      `    throw new Error(label + ' returned unexpected hash output: ' + value)\n` +
      `  }\n` +
      `}\n\n` +
      `await initZkap()\n` +
      `assertHash('root ESM', await generateHash(['1']))\n` +
      `assertHash('node ESM', await generateNodeHash(['1']))\n` +
      `console.log('Node ESM smoke OK')\n`,
  )
  run('node', ['esm-smoke.mjs'], { cwd: consumerDir })
}

function smokeBrowserConsumer(packedPackages) {
  console.log('\n== Browser/Vite packed consumer ==')
  const consumerDir = join(tmpRoot, 'browser-consumer')
  const srcDir = join(consumerDir, 'src')
  mkdirSync(srcDir, { recursive: true })

  writeJson(join(consumerDir, 'package.json'), {
    name: 'zkap-zkp-packed-browser-consumer',
    private: true,
    type: 'module',
    scripts: {
      build: 'vite build',
    },
    dependencies: dependencySpecs(packedPackages),
    overrides: dependencyOverrides(packedPackages),
  })

  run('npm', [
    'install',
    '--no-audit',
    '--no-fund',
    '--omit=optional',
    '--omit=peer',
    '--package-lock=false',
    '--fetch-retries=0',
  ], { cwd: consumerDir })

  writeFileSync(
    join(consumerDir, 'index.html'),
    `<div id="app"></div><script type="module" src="/src/main.js"></script>\n`,
  )
  writeFileSync(
    join(srcDir, 'main.js'),
    `import { generateHash, initZkap } from '@baerae/zkap-zkp/wasm'\n` +
      `import initRawWasm, { generateHash as generateRawWasmHash } from '@baerae/zkap-zkp-wasm'\n\n` +
      `async function main() {\n` +
      `  const hashPattern = /^0x[0-9a-f]{64}$/i\n` +
      `  await initZkap()\n` +
      `  const facadeHash = await generateHash(['1'])\n` +
      `  await initRawWasm()\n` +
      `  const directHash = generateRawWasmHash(['1'])\n\n` +
      `  if (!hashPattern.test(facadeHash)) {\n` +
      `    throw new Error('unexpected facade hash output: ' + facadeHash)\n` +
      `  }\n` +
      `  if (!hashPattern.test(directHash)) {\n` +
      `    throw new Error('unexpected direct wasm hash output: ' + directHash)\n` +
      `  }\n\n` +
      `  document.getElementById('app').textContent = facadeHash + ' ' + directHash\n` +
      `}\n\n` +
      `main().catch((error) => {\n` +
      `  document.getElementById('app').textContent = String(error?.message ?? error)\n` +
      `  throw error\n` +
      `})\n`,
  )

  const viteBin = resolveViteBin()
  run(process.execPath, [viteBin, 'build'], { cwd: consumerDir })
}

function resolveViteBin() {
  const candidates = [
    resolve(rootDir, 'node_modules/.bin/vite'),
  ]
  const existing = candidates.find((candidate) => existsSync(candidate))
  if (existing) return existing

  const toolingDir = join(tmpRoot, 'browser-tooling')
  mkdirSync(toolingDir, { recursive: true })
  writeJson(join(toolingDir, 'package.json'), {
    name: 'zkap-zkp-browser-smoke-tooling',
    private: true,
    type: 'module',
    devDependencies: {
      vite: '^6.0.0',
    },
  })
  run('npm', [
    'install',
    '--no-audit',
    '--no-fund',
    '--package-lock=false',
    '--fetch-retries=0',
  ], { cwd: toolingDir })
  return resolve(toolingDir, 'node_modules/vite/bin/vite.js')
}

function main() {
  const expectedPlatformPackage = expectedRuntimePlatformPackage()
  if (!expectedPlatformPackage) {
    throw new Error(
      `No Node native platform package is defined for ${process.platform}/${process.arch}`,
    )
  }
  if (!hasBinary(expectedPlatformPackage)) {
    throw new Error(
      `Missing current Node native binary ${expectedPlatformPackage.dir}/${expectedPlatformPackage.binary}. ` +
        'Build or download release artifacts before running packed consumer smoke.',
    )
  }

  const platformPackages = installablePlatformPackages()
  const packageDirs = [
    'packages/sdk-wasm',
    'packages/sdk-node',
    'packages/sdk-react-native',
    'packages/sdk',
    ...platformPackages.map((pkg) => pkg.dir),
  ]

  console.log(`Packed consumer smoke temp dir: ${tmpRoot}`)
  const packedPackages = packageDirs.map(packPackage)
  assertPackedInternalVersions(packedPackages)
  const rnPackage = packedPackages.find((pkg) => pkg.name === '@baerae/zkap-zkp-react-native')
  if (!rnPackage) {
    throw new Error('Internal error: React Native package was not packed')
  }

  smokeReactNativeTarball(rnPackage)
  smokeNodeConsumer(packedPackages)
  smokeBrowserConsumer(packedPackages)

  console.log('\nPacked consumer smoke OK')
}

let failed = false
try {
  main()
} catch (error) {
  failed = true
  console.error(error)
  process.exitCode = 1
} finally {
  if (process.env.ZKAP_KEEP_CONSUMER_SMOKE === '1' || failed) {
    console.error(`Packed consumer smoke temp dir kept at ${tmpRoot}`)
  } else {
    rmSync(tmpRoot, { recursive: true, force: true })
  }
}
