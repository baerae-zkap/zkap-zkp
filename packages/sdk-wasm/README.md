# `@baerae/zkap-zkp-wasm`

WebAssembly bindings for zkap-zkp.

Install:

```bash
npm install @baerae/zkap-zkp-wasm
```

```ts
import init, { generateHash, generateAnchor } from '@baerae/zkap-zkp-wasm'

await init()
const hash = generateHash(['0x1', '0x2'])
```

For server-side proof generation and verification, use `@baerae/zkap-zkp`.
