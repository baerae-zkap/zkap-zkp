# React Native Guide

Setup and usage guide for `@baerae/zkap-zkp` in React Native.

## Requirements

| Requirement | Minimum |
|-------------|---------|
| Expo SDK | 51+ |
| `expo-modules-core` | 1.12.0+ (New Architecture) |
| React Native | 0.74+ |
| iOS | 15.0+ |
| Android | API 24+ (NDK required) |

The package includes pre-built native binaries:
- iOS: XCFramework (arm64 device + x86_64/arm64 simulator)
- Android: `.so` libraries (arm64-v8a, x86_64)

## Installation

```bash
npx expo install @baerae/zkap-zkp
```

If your project does not use Expo, install the peer dependencies manually:

```bash
npm install @baerae/zkap-zkp expo-modules-core
```

For `downloadRelease()` / `loadCircuitConfig()`, install Expo FileSystem:

```bash
npx expo install expo-file-system
```

### iOS Setup

```bash
cd ios && pod install
```

### Android Setup

No additional setup required. The native `.so` libraries are bundled in the package.

### Verify Installation

```typescript
import { generateHash } from '@baerae/zkap-zkp';

const hash = await generateHash(['0x1', '0x2']);
console.log(hash); // '0x...'
```

If this throws a native module error, ensure:
1. Expo New Architecture is enabled
2. `expo-modules-core >= 1.12.0`
3. iOS: `pod install` has been run after installation
4. The app has been rebuilt (not just a JS reload)

## API Overview

All functions are **async** (they bridge to native Rust code via UniFFI).

| Function | Config required? | Description |
|----------|-----------------|-------------|
| `generateHash` | No | Poseidon hash of field elements |
| `generateAudHash` | Yes | Audience hash for proof binding |
| `generateLeafHash` | Yes | Merkle leaf hash (issuer + RSA key) |
| `generateAnchor` | Yes | Threshold anchor from credential secrets |
| `downloadRelease` | No | Download/cache a remote proving bundle as `manifestDir` |
| `loadCircuitConfig` | No | Read bundle `config.json` as camelCase config |
| `prove` | Yes | Groth16 proof generation (requires PK) |

For full type signatures, see the [API Reference](API_REFERENCE.md).

## Config

The public facade uses **camelCase** field names in every runtime. The legacy
`@baerae/zkap-zkp-react-native` package still accepts its historical snake_case
shape.

```typescript
import type { CircuitConfig } from '@baerae/zkap-zkp';

const config: CircuitConfig = {
  maxJwtB64Len: 1024,
  maxPayloadB64Len: 640,
  maxAudLen: 155,
  maxExpLen: 20,
  maxIssLen: 93,
  maxNonceLen: 93,
  maxSubLen: 93,
  n: 6,
  k: 3,
  treeHeight: 4,
  numAudienceLimit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbiddenString: 'forbidden',
};
```

## Hash Functions (No Setup Required)

These work immediately after installation with no proving key or network access:

```typescript
import {
  generateHash,
  generateAudHash,
  generateLeafHash,
  generateAnchor,
} from '@baerae/zkap-zkp';

// Poseidon hash
const hash = await generateHash(['0x1', '0x2', '0x3']);

// Audience hash
const audResult = await generateAudHash(config, ['my-audience']);
console.log(audResult.hAudList);     // combined hash
console.log(audResult.audHashes);    // per-slot hashes

// Merkle leaf hash
const leaf = await generateLeafHash(config, 'https://accounts.google.com', rsaPkB64);

// Threshold anchor (requires exactly n secrets)
const secrets = Array.from({ length: config.n }, (_, i) => ({
  sub: `user-${i}`,
  iss: 'https://accounts.google.com',
  aud: 'my-client-id',
}));
const anchor = await generateAnchor(config, secrets);
console.log(anchor.evaluations);
```

## Proof Generation

Proving requires a manifest-backed CRS/proving bundle on disk. The bundle is
not bundled in the npm package. The recommended mobile flow is:

1. Serve the zkap-circuit flat release directory from HTTPS/S3-compatible static hosting.
2. Call `downloadRelease({ baseUrl, shape })`.
3. Call `loadCircuitConfig(release.stagedDir)`.
4. Pass `release.stagedDir` as `manifestDir` to `prove()`.

```typescript
import { downloadRelease, loadCircuitConfig, prove } from '@baerae/zkap-zkp';

const release = await downloadRelease({
  baseUrl: 'https://static.example.com/zkap/releases/v0.1.5',
  shape: '3-of-3',
  expectedReleaseSha: '50aaaa8fe35fc261',
});
const config = await loadCircuitConfig(release.stagedDir);
const result = await prove(config, {
  ...request,
  manifestDir: release.stagedDir,
});
```

Pin `expectedReleaseSha` in production using a trusted release channel. The
value is the first 16 hex chars of SHA256 of `<shape>-SHA256SUMS`.

For local device smoke tests without hosted release artifacts, copy a complete
flat zkap-circuit release directory into app-accessible storage and pass that
directory as `manifestDir`. The staged directory must contain
`manifest.json`, `circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`, `config.json`,
`Groth16Verifier.sol`, and `witness_gen.wasm` from the same release.

```typescript
import { prove } from '@baerae/zkap-zkp';

const result = await prove(config, {
  manifestDir: '/path/to/bundle',
  credentials: [...],
  merkleRoot: '...',
  anchor: anchor.evaluations,
  hSignUserOp: '...',
  random: '...',
});

console.log(result.proofs);            // Solidity-compatible proof arrays
console.log(result.sharedInputs);      // Public inputs shared across JWTs
console.log(result.partialRhsList);    // Per-JWT partial_rhs
console.log(result.jwtExpList);        // Per-JWT expiration
```

### Performance Notes

- Proof generation is CPU-intensive and runs on the native thread
- Expect 30-90 seconds on modern devices (varies by config and device)
- The UI thread remains responsive during proving

## Unsupported Functions

| Function | Status |
|----------|--------|
| `groth16Setup()` | Removed in v0.1.2. Trusted setup is a protocol management operation. |
| `prepareProver()` | Node.js only; mobile proving loads artifacts inside `prove()`. |
| `loadRelease()` | Node.js only; use `downloadRelease()` on React Native. |
| `verify()` | Node.js only in the facade; React Native throws `UnsupportedPlatformError`. |

Calling either function throws an error with a descriptive message.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Cannot find native module 'ZkapReactNative'` | Rebuild the app (`npx expo run:ios` or `npx expo run:android`) |
| `expo-modules-core` version error | `npx expo install expo-modules-core` to get a compatible version |
| `prove()` fails with file not found | Ensure the manifest-backed bundle exists at `manifestDir` |
| Slow proof generation | Expected. Groth16 proving is CPU-intensive on mobile. |
