# zkap-zkp Node.js Example

Examples using `@baerae/zkap-zkp-node` — the native Node.js binding.

## Prerequisites

- Node.js 18+
- A pre-built `.node` binary for your platform (darwin-arm64, darwin-x64, linux-x64-gnu, or linux-x64-musl)

## Setup

```bash
cd examples/node
npm install
```

`@baerae/zkap-zkp-node` is referenced as a local file dependency from `packages/sdk-node`.
If no binary exists for your platform, build it first:

```bash
cd ../../packages/sdk-node
npm run build     # napi build --platform --release
```

## Hash Example

Runs `generateHash`, `generateAudHash`, and `generateAnchor`.

```bash
node hash-basic.js
```

Expected output:

```
generateHash: 0x1e706b0afc828a5262be1773734e80df7fa9c0aa25c8fd5dfb008122a62e65ca
generateAudHash hAudList: 0x05d13fd6...
generateAudHash audHashes[0]: 0x0ad8c403...
generateAnchor evaluations[0]: 0x2481e387...

All done.
```

## Proof Example (groth16Setup → prove → verify)

> **Warning:** `groth16Setup` performs a full Groth16 trusted setup and may take several minutes.

```bash
node proof-basic.js
```

Uses `packages/sdk-node/__test__/mock_proof_input.json` as the circuit input.
`ZKAP_SKIP_MANIFEST_CHECK=1` bypasses manifest validation (for local testing only).

Expected output:

```
[1/3] groth16Setup... (may take several minutes)
  done in 4.8s
  pk: 354088304 bytes, vk: 520 bytes

[2/3] prove...
  done in 16.3s
  proofs: 3, publicInputs: 3

[3/3] verify...
  proof[0]: valid ✓
  proof[1]: valid ✓
  proof[2]: valid ✓

All done.
```

## Notes

- `generateLeafHash` requires a real JWT RS256 public key (base64 DER encoded) and is not included in these examples.
- Proof functions (`groth16Setup`, `prove`, `verify`) are Node.js only. They are not supported in WASM.
