# `@baerae/zkap-zkp`

Node.js SDK for zkap-zkp.

Install:

```bash
npm install @baerae/zkap-zkp
```

This package pulls in `@baerae/zkap-zkp-node` and the matching platform binary package internally.

```ts
import { generateHash, generateAnchor, prove } from '@baerae/zkap-zkp'

const hash = generateHash(['0x1', '0x2'])
const proof = prove(config, request)
```

For browser and bundler usage, install `@baerae/zkap-zkp-wasm`.
