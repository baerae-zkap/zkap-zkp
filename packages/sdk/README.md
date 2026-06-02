# `@baerae/zkap-zkp`

Compatibility facade for the zkap-zkp runtime SDK packages. New applications
should install exactly one runtime package:

- Node.js: `@baerae/zkap-zkp-node`
- Browser/WebAssembly: `@baerae/zkap-zkp-wasm`
- React Native: `@baerae/zkap-zkp-react-native`

This facade keeps the historical import paths, but the runtime implementations
are optional peers. `npm install @baerae/zkap-zkp` alone is not enough to run
the SDK; install exactly one matching runtime package alongside it.

```bash
# Node.js
npm install @baerae/zkap-zkp @baerae/zkap-zkp-node

# Browser/WebAssembly
npm install @baerae/zkap-zkp @baerae/zkap-zkp-wasm

# React Native
npx expo install @baerae/zkap-zkp @baerae/zkap-zkp-react-native
```

```ts
import { generateHash, generateAnchor, initZkap } from '@baerae/zkap-zkp'

await initZkap() // optional no-op on Node/RN, preloads WASM in browsers
const hash = await generateHash(['0x1', '0x2'])
const anchor = await generateAnchor(config, secrets)
```

The root API is Promise-based in every runtime. Internally this package resolves
to `@baerae/zkap-zkp-node`, `@baerae/zkap-zkp-wasm`, or
`@baerae/zkap-zkp-react-native` through package export conditions, but it does
not install all three runtimes for you. npm cannot reliably infer the target
runtime at install time, so applications choose the runtime package explicitly.

## Runtime-specific imports

Use these only when you need to pin a runtime explicitly:

```ts
import { generateHash } from '@baerae/zkap-zkp/node'
import { initZkap } from '@baerae/zkap-zkp/wasm'
import { prove } from '@baerae/zkap-zkp/react-native'
```

Node.js synchronous compatibility is available at:

```ts
import { generateHash } from '@baerae/zkap-zkp/node-sync'

const hash = generateHash(['0x1', '0x2'])
```

## Proving bundles

Large CRS/proving artifacts are not bundled in npm. Serve the zkap-circuit flat
release directory from HTTPS/S3-compatible static hosting and let the SDK create
the local `manifestDir`:

```ts
import {
  downloadRelease,
  loadCircuitConfig,
  prove,
} from '@baerae/zkap-zkp'

const release = await downloadRelease({
  baseUrl: 'https://static.example.com/zkap/releases/v0.1.5',
  shape: '3-of-3',
  expectedReleaseSha: '50aaaa8fe35fc261',
})
const config = await loadCircuitConfig(release.stagedDir)
const proof = await prove(config, {
  ...request,
  manifestDir: release.stagedDir,
})
```

React Native uses `expo-file-system` for this helper. Install it with
`npx expo install expo-file-system` if your app does not already include it.

Integrity differs by runtime. On Node.js, `downloadRelease` and `loadRelease`
stream every artifact through SHA256 and verify it against the release's
`<shape>-SHA256SUMS` (plus the optional `expectedReleaseSha` pin) before staging.
On React Native, `downloadRelease` verifies the small `manifest.json`/`config.json`
hashes and checks each large artifact's **size** during download; the native
`prove()` path then re-applies the manifest SHA256 gate, so a corrupted artifact
fails at `prove()` rather than at download time. Neither path enforces a specific
zkap-circuit revision — ensure the bundle you serve was built from a circuit
revision compatible with this SDK.

For mobile, `downloadRelease` reports whole-release progress (`percent`) and
accepts an `AbortSignal` for cancellation, and `getCachedReleaseInfo` checks for a
staged bundle offline. See the [React Native guide](../../docs/REACT_NATIVE_GUIDE.md#large-download-ux).

## Platform notes

- Node.js supports hash helpers, release download/loading, proving, and verification.
- WebAssembly supports hash helpers only. `prove`, `prepareProver`,
  `downloadRelease`, `loadRelease`, `loadCircuitConfig`, and `verify` throw
  `UnsupportedPlatformError`.
- React Native supports hash helpers, `downloadRelease`, `loadCircuitConfig`,
  and on-device proving. Node-only helpers throw `UnsupportedPlatformError`.
- `normalizeCircuitConfig` is available in every runtime and converts release
  `config.json` snake_case fields to the facade's camelCase `CircuitConfig`.
