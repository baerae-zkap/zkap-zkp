# zkap-zkp SDK

Zero-Knowledge Proof SDK for Node.js, WebAssembly, and React Native, based on Groth16 (BN254) and Poseidon hash.

## Packages

| Package | Platform | Install |
|---------|----------|---------|
| [`@baerae/zkap-zkp`](./packages/sdk) | Node.js / Browser WebAssembly / React Native | `npm install @baerae/zkap-zkp` |

`@baerae/zkap-zkp` resolves runtime implementations through internal packages:
`@baerae/zkap-zkp-node`, `@baerae/zkap-zkp-wasm`, `@baerae/zkap-zkp-react-native`,
and platform-specific optional native binary packages. Most users should install
only `@baerae/zkap-zkp`.

## Capability Matrix

### Core API

Functions actively used in production integrations.

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
npm install @baerae/zkap-zkp
```

```typescript
import { initZkap, generateHash, generateAudHash, generateAnchor } from '@baerae/zkap-zkp';

await initZkap(); // optional no-op on Node/RN, preloads WASM in browsers

// Hash functions work immediately (no setup required)
const hash = await generateHash(['0x1', '0x2']);

// Audience hash
const audResult = await generateAudHash(config, ['my-audience']);

// Threshold anchor (requires exactly n secrets)
const anchor = await generateAnchor(config, secrets);
```

For proving, download or stage a manifest-backed CRS bundle first. The package
provides `downloadRelease()` for a flat zkap-circuit release directory served
over HTTPS/S3-compatible static hosting:

```typescript
import { downloadRelease, loadCircuitConfig, prove } from '@baerae/zkap-zkp';

const release = await downloadRelease({
  baseUrl: 'https://static.example.com/zkap/releases/v0.1.5',
  shape: '3-of-3',
  // Pin this in production after reading the releaseSha from a trusted channel.
  expectedReleaseSha: '50aaaa8fe35fc261',
});
const config = await loadCircuitConfig(release.stagedDir);
const result = await prove(config, { manifestDir: release.stagedDir, ...request });
```

## Quick Start -- Browser (WebAssembly)

```typescript
import { initZkap, generateHash, generateAnchor, generateAudHash } from '@baerae/zkap-zkp';

await initZkap(); // Initialize WASM module
const hash = await generateHash(['0x1', '0x2']);
```

## Quick Start -- React Native (Expo)

```bash
npx expo install @baerae/zkap-zkp
```

```typescript
import { downloadRelease, generateHash, generateAnchor, loadCircuitConfig, prove } from '@baerae/zkap-zkp';

// Hash functions (no setup required)
const hash = await generateHash(['0x1', '0x2']);

// Proving (downloads/caches a CRS/proving bundle on disk)
const release = await downloadRelease({
  baseUrl: 'https://static.example.com/zkap/releases/v0.1.5',
  shape: '3-of-3',
});
const config = await loadCircuitConfig(release.stagedDir);
const result = await prove(config, { manifestDir: release.stagedDir, ...request });
```

> Requires Expo New Architecture (`expo-modules-core >= 1.12.0`). Native binaries (iOS XCFramework, Android `.so`) are bundled in the package. `downloadRelease()` on React Native uses `expo-file-system`; install it with `npx expo install expo-file-system` if your app does not already include it.

See the [React Native Guide](docs/REACT_NATIVE_GUIDE.md) for full setup instructions.

## Naming Conventions

The public `@baerae/zkap-zkp` facade uses **camelCase** config fields in every
runtime. The legacy React Native package still accepts its historical snake_case
shape.

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
- **Node sync compatibility:** use `@baerae/zkap-zkp/node-sync` when a synchronous
  Node-only API is required.

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
