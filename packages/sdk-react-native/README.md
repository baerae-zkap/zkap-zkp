# `@baerae/zkap-zkp-react-native`

React Native SDK for zkap-zkp with Expo modules integration.

Install:

```bash
npm install @baerae/zkap-zkp-react-native
```

Requires Expo New Architecture and the following peer dependencies:

- `expo`
- `expo-crypto`
- `expo-file-system`
- `expo-modules-core`
- `react-native`

```ts
import { generateHash, generateAnchor } from '@baerae/zkap-zkp-react-native'

const hash = await generateHash(['0x1', '0x2'])
const anchor = await generateAnchor(config, secrets)
```

The npm package bundles the iOS XCFramework and Android `.so` libraries produced by CI.
