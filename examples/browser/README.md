# zkap-zkp Browser (WebAssembly) Example

Browser example using `@baerae/zkap-zkp-wasm` with Vite.

## Prerequisites

- Node.js 18+
- wasm-pack: `cargo install wasm-pack`

## Setup

### 1. Build the WASM package

```bash
cd ../../packages/sdk-wasm
wasm-pack build --target web --out-dir pkg --out-name zkap_zkp_wasm
node scripts/patch-pkg-name.mjs
```

### 2. Install dependencies

```bash
cd ../../examples/browser
npm install
```

`@baerae/zkap-zkp-wasm` is referenced as a local file dependency from `packages/sdk-wasm/pkg`.

## Run

```bash
npm run dev
```

Open http://localhost:5173 in your browser. You should see:

```
WASM initialized

generateHash(['0x1','0x2','0x3'])
  → 0x1e706b0afc828a5262be1773734e80df7fa9c0aa25c8fd5dfb008122a62e65ca

generateAudHash
  hAudList     → 0x05d13fd6...
  audHashes[0] → 0x0ad8c403...

generateAnchor (n=6)
  evaluations[0] → 0x2481e387...

All done.
```

## File Overview

| File | Purpose |
|------|---------|
| `main.js` | WASM initialization and hash function calls |
| `index.html` | Output display |
| `vite.config.js` | `vite-plugin-wasm` configuration |
| `package.json` | Local sdk-wasm dependency |

## Notes

- `await init()` explicitly initializes the WASM binary (required for the `web` target).
- `prove`, `verify`, and `groth16Setup` are not supported in WASM. Use `@baerae/zkap-zkp-node` for server-side proving.
- `generateLeafHash` requires a real JWT RS256 public key (base64 DER encoded) and is not included in this example.
