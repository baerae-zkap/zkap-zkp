# `@baerae/zkap-zkp-wasm`

WebAssembly bindings for zkap-zkp.

Install:

```bash
npm install @baerae/zkap-zkp-wasm
```

```ts
import initZkap, { generateHash, generateAnchor } from '@baerae/zkap-zkp-wasm'

await initZkap()
const hash = generateHash(['0x1', '0x2'])
```

This direct runtime package exposes the wasm-pack API. Initialize the WASM
module once, then call the hash helpers synchronously. Use `@baerae/zkap-zkp`
with this package when you need the Promise-based compatibility facade.
