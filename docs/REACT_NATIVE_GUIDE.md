# React Native Guide

Setup and usage guide for `@baerae/zkap-zkp-react-native`.

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
- Android: `.so` libraries (arm64-v8a, armeabi-v7a, x86_64)

## Installation

```bash
npx expo install @baerae/zkap-zkp-react-native
```

If your project does not use Expo, install the peer dependencies manually:

```bash
npm install @baerae/zkap-zkp-react-native expo-modules-core
```

### iOS Setup

```bash
cd ios && pod install
```

### Android Setup

No additional setup required. The native `.so` libraries are bundled in the package.

### Verify Installation

```typescript
import { generateHash } from '@baerae/zkap-zkp-react-native';

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

## Config (snake_case)

React Native uses **snake_case** field names, unlike Node.js/WASM which use camelCase.

```typescript
import type { CircuitConfig } from '@baerae/zkap-zkp-react-native';

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
} from '@baerae/zkap-zkp-react-native';

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

Proving requires a ~400 MB proving key file on disk. The proving key is not bundled in the npm package; download it separately (e.g., from S3) and provide the file path to `prove()`.

```typescript
import { prove } from '@baerae/zkap-zkp-react-native';

const result = await prove(config, {
  pk_path: '/path/to/pk.bin',
  jwts: [...],
  pk_ops: [...],
  merkle_paths: [...],
  leaf_indices: [...],
  root: '...',
  anchor_evals: anchor.evaluations,
  hanchor: '...',
  h_sign_user_op: '...',
  random: '...',
  aud_hash_list: audResult.aud_hashes,
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
| `verify()` | Removed in v0.1.2. Verification is performed on-chain or server-side. |

Calling either function throws an error with a descriptive message.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Cannot find native module 'ZkapSdk'` | Rebuild the app (`npx expo run:ios` or `npx expo run:android`) |
| `expo-modules-core` version error | `npx expo install expo-modules-core` to get a compatible version |
| `prove()` fails with file not found | Ensure the proving key file exists at the path passed as `pk_path` |
| Slow proof generation | Expected. Groth16 proving is CPU-intensive on mobile. |

## Example App

A full smoke test app is available at [`examples/expo-example/`](../examples/expo-example/). It exercises all five API functions with mock inputs.

```bash
cd examples/expo-example
npm install
npx expo run:ios    # or npx expo run:android
```
