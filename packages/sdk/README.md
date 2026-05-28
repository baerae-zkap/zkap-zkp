# `@baerae/zkap-zkp`

Multi-runtime SDK for zkap-zkp. Install this package once and use the same
public import from Node.js, browser/WebAssembly, and React Native.

```bash
npm install @baerae/zkap-zkp
```

```ts
import { generateHash, generateAnchor, initZkap } from '@baerae/zkap-zkp'

await initZkap() // optional no-op on Node/RN, preloads WASM in browsers
const hash = await generateHash(['0x1', '0x2'])
const anchor = await generateAnchor(config, secrets)
```

The root API is Promise-based in every runtime. Internally this package resolves
to `@baerae/zkap-zkp-node`, `@baerae/zkap-zkp-wasm`, or
`@baerae/zkap-zkp-react-native` through package export conditions.

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
  ZKAP_CIRCUIT_COMMIT,
  downloadRelease,
  loadCircuitConfig,
  prove,
} from '@baerae/zkap-zkp'

const release = await downloadRelease({
  baseUrl: 'https://static.example.com/zkap/releases/v0.1.5',
  shape: '3-of-3',
  expectedReleaseSha: '50aaaa8fe35fc261',
  expectedCircuitCommit: ZKAP_CIRCUIT_COMMIT,
})
const config = await loadCircuitConfig(release.stagedDir)
const proof = await prove(config, {
  ...request,
  manifestDir: release.stagedDir,
})
```

React Native uses `expo-file-system` for this helper. Install it with
`npx expo install expo-file-system` if your app does not already include it.

`downloadRelease` and Node's `loadRelease` reject release manifests whose
`build.circuit_commit` does not match `ZKAP_CIRCUIT_COMMIT` by default. Pass
`expectedCircuitCommit` to pin a specific compatible release, and reserve
`allowCircuitCommitMismatch` for local development bundles only.

## Platform notes

- Node.js supports hash helpers, release download/loading, proving, and verification.
- WebAssembly supports hash helpers only. `prove`, `prepareProver`,
  `downloadRelease`, `loadRelease`, `loadCircuitConfig`, and `verify` throw
  `UnsupportedPlatformError`.
- React Native supports hash helpers, `downloadRelease`, `loadCircuitConfig`,
  and on-device proving. Node-only helpers throw `UnsupportedPlatformError`.
- `normalizeCircuitConfig` is available in every runtime and converts release
  `config.json` snake_case fields to the facade's camelCase `CircuitConfig`.
