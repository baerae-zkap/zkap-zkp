#!/usr/bin/env node
/**
 * sync-versions.mjs
 *
 * Synchronizes the version field across all published packages and updates
 * internal package dependency references to match.
 *
 * Usage:
 *   node scripts/sync-versions.mjs <version>
 *   node scripts/sync-versions.mjs 0.2.0
 */

import { readFileSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const version = process.argv[2];
if (!version) {
  console.error('Error: version argument required');
  console.error('Usage: node scripts/sync-versions.mjs <version>');
  process.exit(1);
}

if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) {
  console.error(`Error: invalid version format: "${version}"`);
  console.error('Expected semver, e.g. 0.2.0 or 1.0.0-beta.1');
  process.exit(1);
}

const PLATFORM_PACKAGES = [
  'platform-packages/node-darwin-x64',
  'platform-packages/node-darwin-arm64',
  'platform-packages/node-linux-x64-gnu',
  'platform-packages/node-linux-x64-musl',
];

function updatePackageJson(relPath, updater) {
  const absPath = resolve(root, relPath, 'package.json');
  const raw = readFileSync(absPath, 'utf8');
  const pkg = JSON.parse(raw);
  const before = pkg.version;
  updater(pkg);
  writeFileSync(absPath, JSON.stringify(pkg, null, 2) + '\n');
  console.log(`  ${relPath}/package.json  ${before} → ${pkg.version}`);
}

console.log(`\nSyncing all packages to version ${version}\n`);

// 1. Platform packages
for (const dir of PLATFORM_PACKAGES) {
  updatePackageJson(dir, (pkg) => {
    pkg.version = version;
  });
}

// 2. sdk-node: version + optionalDependencies
updatePackageJson('packages/sdk-node', (pkg) => {
  pkg.version = version;
  for (const key of Object.keys(pkg.optionalDependencies ?? {})) {
    pkg.optionalDependencies[key] = version;
  }
});

// 3. sdk facade
updatePackageJson('packages/sdk', (pkg) => {
  pkg.version = version;
  if (pkg.dependencies?.['@baerae/zkap-zkp-node']) {
    pkg.dependencies['@baerae/zkap-zkp-node'] = version;
  }
});

// 4. sdk-wasm
updatePackageJson('packages/sdk-wasm', (pkg) => {
  pkg.version = version;
});

// 5. sdk-react-native
updatePackageJson('packages/sdk-react-native', (pkg) => {
  pkg.version = version;
});

console.log('\nDone.\n');
