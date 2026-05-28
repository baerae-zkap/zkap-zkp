# zkap-zkp SDK

Zero-Knowledge Proof SDK for Node.js, WebAssembly, and React Native, based on Groth16 (BN254) and Poseidon hash.

## Packages

| Package | Platform | Install |
|---------|----------|---------|
| [`@baerae/zkap-zkp-sdk-node`](./packages/sdk-node) | Node.js | `npm install @baerae/zkap-zkp-sdk-node` |
| [`@baerae/zkap-zkp-sdk-wasm`](./packages/sdk-wasm) | Browser WebAssembly | `npm install @baerae/zkap-zkp-sdk-wasm` |
| [`@baerae/zkap-zkp-sdk-react-native`](./packages/sdk-react-native) | React Native | `npm install @baerae/zkap-zkp-sdk-react-native` |
| [`@baerae/zkap-zkp`](./packages/sdk) | Compatibility facade | `npm install @baerae/zkap-zkp <runtime package>` |

Install the package for the runtime you actually run. The runtime-specific
packages are the recommended default for new applications.

The compatibility facade keeps the historical `@baerae/zkap-zkp` import paths,
but its runtime packages are optional peers. Installing `@baerae/zkap-zkp` by
itself does not install a Node, WebAssembly, or React Native implementation.
Install exactly one matching runtime package beside it when you need the facade:

```bash
# Node.js facade API
npm install @baerae/zkap-zkp @baerae/zkap-zkp-sdk-node

# Browser/WebAssembly facade API
npm install @baerae/zkap-zkp @baerae/zkap-zkp-sdk-wasm

# React Native facade API
npx expo install @baerae/zkap-zkp @baerae/zkap-zkp-sdk-react-native
```

This package manager model is intentional: npm cannot reliably infer whether a
consumer project is a Node.js server, a browser bundle, or a React Native app at
install time, so the runtime package is selected explicitly by the application.

The runtime packages expose their existing runtime-specific APIs. Use the
`@baerae/zkap-zkp` facade only when you need the uniform Promise-based API and
helpers such as `downloadRelease()`.

## Capability Matrix

### Core API

Functions actively used in production integrations through the compatibility
facade.

| API | Node.js | WASM | React Native | Notes |
|-----|---------|------|--------------|-------|
| `generateHash` | async | async | async | Poseidon hash |
| `generateAudHash` | async | async | async | Audience hash |
| `generateAnchor` | async | async | async | Threshold anchor |
| `prove` | async | -- | async | Requires CRS/proving bundle |
| `downloadRelease` | async | -- | async | Downloads/stages a release bundle into `manifestDir` |
| `loadCircuitConfig` | async | -- | async | Reads `config.json` as facade camelCase config |

### Utility API

Available for custom integrations. Not used in current production deployments.

| API | Node.js | WASM | React Native | Notes |
|-----|---------|------|--------------|-------|
| `generateLeafHash` | async | async | async | Merkle leaf hash |
| `normalizeCircuitConfig` | sync | sync | sync | Converts release `config.json` snake_case to facade camelCase |

> `prove` is not available in WASM due to memory constraints. Use Node.js (server-side) or React Native (on-device).

> Trusted setup is not included in the public facade. `verify` is available in Node.js and throws `UnsupportedPlatformError` in WASM and React Native.

## Quick Start

```bash
npm install @baerae/zkap-zkp-sdk-node
```

```typescript
import { generateHash, generateAudHash, generateAnchor } from '@baerae/zkap-zkp-sdk-node';

const hash = generateHash(['0x1', '0x2']);

// Audience hash
const audResult = generateAudHash(config, ['my-audience']);

// Threshold anchor (requires exactly n secrets)
const anchor = generateAnchor(config, secrets);
```

For proving, stage a manifest-backed CRS bundle first:

```typescript
import { loadRelease, prove } from '@baerae/zkap-zkp-sdk-node';

const release = loadRelease({
  releaseDir: '/path/to/flat-release',
  shape: '3-of-3',
});
const result = prove(config, { manifestDir: release.stagedDir, ...request });
```

## Quick Start -- Browser (WebAssembly)

```bash
npm install @baerae/zkap-zkp-sdk-wasm
```

```typescript
import initZkap, { generateHash, generateAnchor, generateAudHash } from '@baerae/zkap-zkp-sdk-wasm';

await initZkap(); // Initialize WASM module
const hash = generateHash(['0x1', '0x2']);
```

## Quick Start -- React Native (Expo)

```bash
npx expo install @baerae/zkap-zkp-sdk-react-native
```

```typescript
import { generateHash, generateAnchor, prove } from '@baerae/zkap-zkp-sdk-react-native';

// Hash functions (no setup required)
const hash = await generateHash(['0x1', '0x2']);

// Proving expects an app-accessible manifest directory containing the CRS bundle.
const result = await prove(config, { manifest_dir: manifestDir, ...request });
```

> Requires Expo New Architecture (`expo-modules-core >= 1.12.0`). Native binaries (iOS XCFramework, Android `.so`) are bundled in the package. The compatibility facade's React Native `downloadRelease()` helper uses `expo-file-system`; install it with `npx expo install expo-file-system` if your app uses that helper.

See the [React Native Guide](docs/REACT_NATIVE_GUIDE.md) for full setup instructions.

## Naming Conventions

The compatibility facade uses **camelCase** config fields in every runtime.
The direct React Native runtime package keeps its historical snake_case shape.

| Node.js / WASM | React Native |
|-----------------|--------------|
| `maxJwtB64Len` | `max_jwt_b64_len` |
| `treeHeight` | `tree_height` |
| `numAudienceLimit` | `num_audience_limit` |
| `forbiddenString` | `forbidden_string` |

See the [API Reference](docs/API_REFERENCE.md) for full type definitions.

## Proving Bundle

The CRS/proving bundle is **not bundled in npm**. Large proving artifacts should
be served separately (for example from S3 or a CDN), then converted to the
`manifestDir` layout consumed by `prove()`.

Use `downloadRelease({ baseUrl, shape })` when the remote directory uses the
zkap-circuit flat release layout:

```text
<baseUrl>/
  3-of-3-manifest.json
  3-of-3-circuit.ar1cs
  3-of-3-pk.bin
  3-of-3-vk.bin
  3-of-3-pvk.bin
  3-of-3-Groth16Verifier.sol
  3-of-3-config.json
  3-of-3-SHA256SUMS
  witness_gen.wasm
```

`downloadRelease()` returns `{ stagedDir, manifestJson, shape, releaseSha }`.
Pass `stagedDir` as `manifestDir`. In production, pin `expectedReleaseSha` to
the first 16 hex chars of SHA256 of `<shape>-SHA256SUMS` from a trusted release
channel.

- **WASM:** `prove()` is not supported.
- **Browser/WASM:** `downloadRelease()` is not supported because browsers cannot
  expose a native filesystem `manifestDir` to the prover.
- **Node sync compatibility:** the direct `@baerae/zkap-zkp-sdk-node` package is
  synchronous. The compatibility facade also exposes `@baerae/zkap-zkp/node-sync`
  for a synchronous Node-only API.

## Documentation

- [API Reference](docs/API_REFERENCE.md) -- function signatures, types, and platform differences
- [React Native Guide](docs/REACT_NATIVE_GUIDE.md) -- installation, setup, and usage for Expo

## Development

```bash
# Build Node.js bindings
cargo build

# Run tests
cargo test

# Lint
cargo clippy --workspace -- -D warnings

# Build WASM
cd packages/sdk-wasm && wasm-pack build --target web

# Build TypeScript facade
cd packages/sdk && npm run build

# Run Node.js tests
cd packages/sdk-node && npm test
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for build setup, testing, and PR guidelines.

To report a security vulnerability, see [SECURITY.md](./SECURITY.md).

## License

Licensed under either of MIT License or Apache License 2.0, at your option.
