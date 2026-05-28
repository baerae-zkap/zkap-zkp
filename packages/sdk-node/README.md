# `@baerae/zkap-zkp-node`

Native Node.js bindings for zkap-zkp.

Install:

```bash
npm install @baerae/zkap-zkp-node
```

```ts
import { generateHash, loadRelease, prove } from '@baerae/zkap-zkp-node'

const hash = generateHash(['0x1', '0x2'])
const release = loadRelease({ releaseDir: '/path/to/flat-release', shape: '3-of-3' })
const proof = prove(config, { manifestDir: release.stagedDir, ...request })
```

This direct runtime package exposes the synchronous napi-rs API and installs
only the current platform's optional native binary package. Use
`@baerae/zkap-zkp` with this package when you need the Promise-based
compatibility facade and helpers such as `downloadRelease()`.
