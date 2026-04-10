# zkap-zkp SDK

Zero-Knowledge Proof SDK for Node.js and WebAssembly, based on Groth16 (BN254) and Poseidon hash.

## Packages

| Package | Platform | Install |
|---------|----------|---------|
| [`@baerae/zkap-zkp`](./packages/sdk) | Node.js | `npm install @baerae/zkap-zkp` |
| [`@baerae/zkap-zkp-wasm`](./packages/sdk-wasm) | Browser / WebAssembly | `npm install @baerae/zkap-zkp-wasm` |
| [`@baerae/zkap-zkp-react-native`](./packages/sdk-react-native) | React Native (Expo) | `npm install @baerae/zkap-zkp-react-native` |

`@baerae/zkap-zkp` resolves its native bindings through internal npm subpackages:
`@baerae/zkap-zkp-node` plus platform-specific optional dependencies. Most users should
ignore those internal packages and install the two public entrypoints above.

## Quick Start — Node.js

```bash
npm install @baerae/zkap-zkp
```

```typescript
import { generateHash, generateAnchor, prove } from '@baerae/zkap-zkp';
import { initArtifacts } from '@baerae/zkap-zkp/artifact-manager';

// Hash functions (no setup required)
const hash = await generateHash(['0x1', '0x2']);

// Proving (requires PK download)
await initArtifacts({
  manifestUrl: 'https://your-bucket.s3.amazonaws.com/zkap/manifest.json',
});
const proof = await prove(request);
```

## Quick Start — Browser (WebAssembly)

```bash
npm install @baerae/zkap-zkp-wasm
```

```typescript
import init, { generateHash, generateAnchor } from '@baerae/zkap-zkp-wasm';

await init(); // Initialize WASM module
const hash = generateHash(['0x1', '0x2']);
```

## Quick Start — React Native (Expo)

```bash
npm install @baerae/zkap-zkp-react-native
```

```typescript
import { generateHash, generateAnchor } from '@baerae/zkap-zkp-react-native';

// Hash functions (no setup required)
const hash = await generateHash(['0x1', '0x2']);
const anchor = await generateAnchor(['0x1', '0x2']);
```

> Requires Expo New Architecture (`expo-modules-core >= 1.12.0`). Native binaries (iOS XCFramework, Android `.so`) are bundled in the package.

## Capability Matrix

| API | Node.js | WebAssembly | Notes |
|-----|---------|-------------|-------|
| `generateHash` | ✅ | ✅ | Poseidon hash |
| `generateAnchor` | ✅ | ✅ | Threshold anchor |
| `generateAudHash` | ✅ | ✅ | Audience hash |
| `generateLeafHash` | ✅ | ✅ | Leaf hash |
| `prove` | ✅ | ❌ | Server only (requires ~400MB proving key) |

## Examples

- [`examples/node/`](./examples/node/) — hash and proof usage with `@baerae/zkap-zkp`
- [`examples/browser/`](./examples/browser/) — WASM hash usage with Vite

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
For release operations and first-publish bootstrapping, see [docs/release-runbook.md](./docs/release-runbook.md).

To report a security vulnerability, see [SECURITY.md](./SECURITY.md).

## License

Licensed under either of MIT License or Apache License 2.0, at your option.
