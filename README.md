# zkap-zkp SDK

Zero-Knowledge Proof SDK for Node.js, WebAssembly, and React Native, based on Groth16 (BN254) and Poseidon hash.

## Packages

| Package | Platform | Install |
|---------|----------|---------|
| [`@baerae/zkap-zkp`](./packages/sdk) | Node.js | `npm install @baerae/zkap-zkp` |
| [`@baerae/zkap-zkp-wasm`](./packages/sdk-wasm) | Browser / WebAssembly | `npm install @baerae/zkap-zkp-wasm` |
| [`@baerae/zkap-zkp-react-native`](./packages/sdk-react-native) | React Native (Expo) | `npx expo install @baerae/zkap-zkp-react-native` |

`@baerae/zkap-zkp` resolves its native bindings through internal npm subpackages:
`@baerae/zkap-zkp-node` plus platform-specific optional dependencies. Most users should
ignore those internal packages and install the public entrypoints above.

## Capability Matrix

### Core API

Functions actively used in production integrations.

| API | Node.js | WASM | React Native | Notes |
|-----|---------|------|--------------|-------|
| `generateHash` | sync | sync | async | Poseidon hash |
| `generateAudHash` | sync | sync | async | Audience hash |
| `generateAnchor` | sync | sync | async | Threshold anchor |
| `prove` | sync | -- | async | Requires ~400 MB proving key |

### Utility API

Available for custom integrations. Not used in current production deployments.

| API | Node.js | WASM | React Native | Notes |
|-----|---------|------|--------------|-------|
| `generateLeafHash` | sync | sync | async | Merkle leaf hash |

> `prove` is not available in WASM due to memory constraints. Use Node.js (server-side) or React Native (on-device).

> `setup` and `verify` are not included in the public SDK. Trusted setup is a protocol management operation; verification is performed on-chain or server-side.

## Quick Start -- Node.js

```bash
npm install @baerae/zkap-zkp
```

```typescript
import { generateHash, generateAudHash, generateAnchor } from '@baerae/zkap-zkp';

// Hash functions work immediately (no setup required)
const hash = generateHash(['0x1', '0x2']);

// Audience hash
const audResult = generateAudHash(config, ['my-audience']);

// Threshold anchor (requires exactly n secrets)
const anchor = generateAnchor(config, secrets);
```

For proving, a proving key file must be available on disk:

```typescript
import { prove } from '@baerae/zkap-zkp';

const result = prove(config, { pkPath: '/path/to/pk.bin', ...request });
```

## Quick Start -- Browser (WebAssembly)

```bash
npm install @baerae/zkap-zkp-wasm
```

```typescript
import init, { generateHash, generateAnchor, generateAudHash } from '@baerae/zkap-zkp-wasm';

await init(); // Initialize WASM module
const hash = generateHash(['0x1', '0x2']);
```

## Quick Start -- React Native (Expo)

```bash
npx expo install @baerae/zkap-zkp-react-native
```

```typescript
import { generateHash, generateAnchor, prove } from '@baerae/zkap-zkp-react-native';

// Hash functions (no setup required)
const hash = await generateHash(['0x1', '0x2']);

// Proving (requires a proving key file on disk)
const result = await prove(config, { pk_path: '/path/to/pk.bin', ...request });
```

> Requires Expo New Architecture (`expo-modules-core >= 1.12.0`). Native binaries (iOS XCFramework, Android `.so`) are bundled in the package.

See the [React Native Guide](docs/REACT_NATIVE_GUIDE.md) for full setup instructions.

## Naming Conventions

Node.js and WASM use **camelCase** config fields. React Native uses **snake_case**.

| Node.js / WASM | React Native |
|-----------------|--------------|
| `maxJwtB64Len` | `max_jwt_b64_len` |
| `treeHeight` | `tree_height` |
| `numAudienceLimit` | `num_audience_limit` |
| `forbiddenString` | `forbidden_string` |

See the [API Reference](docs/API_REFERENCE.md) for full type definitions.

## Proving Key

The proving key (~400 MB) is **not bundled in npm**. Users must download it separately (e.g., from S3) and provide the file path to `prove()`.

- **WASM:** `prove()` is not supported.

## Examples

- [`examples/node/`](./examples/node/) -- hash and proof usage with `@baerae/zkap-zkp`
- [`examples/browser/`](./examples/browser/) -- WASM hash usage with Vite
- [`examples/expo-example/`](./examples/expo-example/) -- React Native smoke test (all 5 API functions)

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
cd packages/sdk && npm test
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for build setup, testing, and PR guidelines.

To report a security vulnerability, see [SECURITY.md](./SECURITY.md).

## License

Licensed under either of MIT License or Apache License 2.0, at your option.
