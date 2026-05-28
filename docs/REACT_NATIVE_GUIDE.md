# React Native Guide

Setup and usage guide for `@baerae/zkap-zkp-sdk-react-native` in React Native.

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
npx expo install @baerae/zkap-zkp-sdk-react-native
```

If your project does not use Expo, install the peer dependencies manually:

```bash
npm install @baerae/zkap-zkp-sdk-react-native expo-modules-core
```

The direct React Native package does not include release-download helpers. If
you use the `@baerae/zkap-zkp` compatibility facade for
`downloadRelease()` / `loadCircuitConfig()`, install the facade beside the
React Native runtime package and add Expo FileSystem:

```bash
npx expo install @baerae/zkap-zkp @baerae/zkap-zkp-sdk-react-native expo-file-system
```

### iOS Setup

```bash
cd ios && pod install
```

### Android Setup

No additional setup required. The native `.so` libraries are bundled in the package.

### Verify Installation

```typescript
import { generateHash } from '@baerae/zkap-zkp-sdk-react-native';

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
| `prove` | Yes | Groth16 proof generation (requires PK) |

For full type signatures, see the [API Reference](API_REFERENCE.md).

## Config

The direct React Native package uses the historical snake_case config shape.
The `@baerae/zkap-zkp` compatibility facade converts its camelCase config to
this shape internally.

```typescript
import type { CircuitConfig } from '@baerae/zkap-zkp-sdk-react-native';

const config: CircuitConfig = {
  max_jwt_b64_len: 1024,
  max_payload_b64_len: 640,
  max_aud_len: 155,
  max_exp_len: 20,
  max_iss_len: 93,
  max_nonce_len: 93,
  max_sub_len: 93,
  n: 6,
  k: 3,
  tree_height: 4,
  num_audience_limit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbidden_string: 'forbidden',
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
} from '@baerae/zkap-zkp-sdk-react-native';

// Poseidon hash
const hash = await generateHash(['0x1', '0x2', '0x3']);

// Audience hash
const audResult = await generateAudHash(config, ['my-audience']);
console.log(audResult.h_aud_list);   // combined hash
console.log(audResult.aud_hashes);   // per-slot hashes

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
not bundled in the npm package. With the direct React Native package, your app
is responsible for placing a validated bundle in app-accessible storage:

1. Serve or bundle a complete zkap-circuit release from a trusted source.
2. Copy/stage the unprefixed manifest directory into app-accessible storage.
3. Pass that directory as `manifest_dir` to `prove()`.

```typescript
import { prove } from '@baerae/zkap-zkp-sdk-react-native';

const result = await prove(config, {
  ...request,
  manifest_dir: manifestDir,
});
```

If you want the SDK to download and stage a remote flat release directory, use
the compatibility facade with this runtime package:

```bash
npx expo install @baerae/zkap-zkp @baerae/zkap-zkp-sdk-react-native expo-file-system
```

```typescript
import { downloadRelease, loadCircuitConfig, prove } from '@baerae/zkap-zkp/react-native';

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
directory as `manifest_dir`. The staged directory must contain
`manifest.json`, `circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`, `config.json`,
`Groth16Verifier.sol`, and `witness_gen.wasm` from the same release.

```typescript
import { prove } from '@baerae/zkap-zkp-sdk-react-native';

const result = await prove(config, {
  manifest_dir: '/path/to/bundle',
  credentials: [...],
  merkle_root: '...',
  anchor: anchor.evaluations,
  h_sign_user_op: '...',
  random: '...',
});

console.log(result.proofs);            // Solidity-compatible proof arrays
console.log(result.shared_inputs);     // Public inputs shared across JWTs
console.log(result.partial_rhs_list);  // Per-JWT partial_rhs
console.log(result.jwt_exp_list);      // Per-JWT expiration
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
| `loadRelease()` | Node.js only. |
| `downloadRelease()` | Available through the `@baerae/zkap-zkp` compatibility facade. |
| `loadCircuitConfig()` | Available through the `@baerae/zkap-zkp` compatibility facade. |
| `verify()` | Node.js only in the facade; React Native throws `UnsupportedPlatformError`. |

Calling unsupported functions throws an error with a descriptive message.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Cannot find native module 'ZkapReactNative'` | Rebuild the app (`npx expo run:ios` or `npx expo run:android`) |
| `expo-modules-core` version error | `npx expo install expo-modules-core` to get a compatible version |
| `prove()` fails with file not found | Ensure the manifest-backed bundle exists at `manifest_dir` |
| Slow proof generation | Expected. Groth16 proving is CPU-intensive on mobile. |
