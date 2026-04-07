# zkap-zkp SDK

Zero-Knowledge Proof SDK for Node.js and WebAssembly, based on Groth16 (BN254) and Poseidon hash.

## Packages

| Package | Platform | Install |
|---------|----------|---------|
| [`@baerae/zkap-zkp`](./packages/sdk) | Node.js | `npm install @baerae/zkap-zkp` |
| [`@baerae/zkap-zkp-wasm`](./packages/sdk-wasm) | Browser / WebAssembly | `npm install @baerae/zkap-zkp-wasm` |

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
await initArtifacts(); // Downloads and caches proving key from S3
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

## Capability Matrix

| API | Node.js | WebAssembly | Notes |
|-----|---------|-------------|-------|
| `generateHash` | ✅ | ✅ | Poseidon hash |
| `generateAnchor` | ✅ | ✅ | Threshold anchor |
| `generateAudHash` | ✅ | ✅ | Audience hash |
| `generateLeafHash` | ✅ | ✅ | Leaf hash |
| `groth16Setup` | ✅ | ❌ | Server only |
| `prove` | ✅ | ❌ | Server only (requires ~400MB proving key) |
| `verify` | ✅ | ❌ | Server only (VK is on-chain) |

## Development

```bash
# Build Node.js bindings
cargo build

# Run tests
cargo test

# Lint
cargo clippy --workspace -- -D warnings

# Build WASM
cd packages/sdk-wasm && wasm-pack build --target bundler

# Run Node.js tests
cd packages/sdk-node && npm test
```

## License

Licensed under either of MIT License or Apache License 2.0, at your option.
