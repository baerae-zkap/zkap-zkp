# `@baerae/zkap-zkp-react-native`

React Native SDK for zkap-zkp with Expo modules integration.

Install:

```bash
npm install @baerae/zkap-zkp-react-native
```

Requires Expo New Architecture and the following peer dependencies:

- `expo`
- `expo-modules-core`
- `react-native`

```ts
import { generateHash, generateAnchor } from '@baerae/zkap-zkp-react-native'

const hash = await generateHash(['0x1', '0x2'])
const anchor = await generateAnchor(config, secrets)
```

The npm package bundles the iOS XCFramework and Android `.so` libraries produced by CI.

`prove()` expects a downloaded zkap-circuit release bundle that includes
`manifest.json`, `pk.bin`, `circuit.ar1cs`, and `witness_gen.wasm` from the same
circuit release. The package does not bundle `witness_gen.wasm`.

On iOS-family targets, `witness_gen.wasm` runs inside a headless `WKWebView`.
The witness output is transferred back to native code with chunked base64,
validated by sha256/length, written to a temp file, and then consumed by the
native proof pipeline. The iOS native binary does not link Wasmtime, Cranelift,
Pulley, or Wasmi.

Android and other non-iOS native targets keep the Wasmtime-backed witness
runtime and pass witness bytes directly into the native proof pipeline without a
React Native bridge transfer.

For App Store submissions, keep the zkap-circuit release URL immutable and pin
the expected release artifact hashes. The SDK validates the release bundle before
proving, but App Review approval is still the host app's responsibility.
