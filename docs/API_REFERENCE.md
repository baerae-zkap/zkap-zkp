# API Reference

Public API for `@baerae/zkap-zkp` (Node.js), `@baerae/zkap-zkp-wasm` (Browser), and `@baerae/zkap-zkp-react-native` (Expo).

## Platform Support

### Core API

Functions actively used in production integrations.

| Function | Node.js | WASM | React Native | Notes |
|----------|---------|------|--------------|-------|
| `generateHash` | sync | sync | async | Poseidon hash |
| `generateAudHash` | sync | sync | async | Audience hash |
| `generateAnchor` | sync | sync | async | Threshold anchor |
| `prove` | sync | -- | async | Requires proving key (~400 MB) |

### Utility API

Available for custom integrations. Not used in current production deployments.

| Function | Node.js | WASM | React Native | Notes |
|----------|---------|------|--------------|-------|
| `generateLeafHash` | sync | sync | async | Merkle leaf hash |

> `setup` and `verify` are not included in the public SDK. Trusted setup is a protocol management operation; verification is performed on-chain or server-side.

> WASM cannot run `prove` due to memory constraints. Calling it throws an error with a message directing you to Node.js or React Native.

## Naming Conventions

Node.js and WASM use **camelCase** for config fields. React Native uses **snake_case**.

| Node.js / WASM | React Native |
|-----------------|--------------|
| `maxJwtB64Len` | `max_jwt_b64_len` |
| `maxPayloadB64Len` | `max_payload_b64_len` |
| `treeHeight` | `tree_height` |
| `numAudienceLimit` | `num_audience_limit` |
| `forbiddenString` | `forbidden_string` |

All other field names (`n`, `k`, `claims`) are identical across platforms.

---

## CircuitConfig

Circuit parameters required by most functions. The config must match the configuration used during trusted setup (CRS generation).

### Node.js / WASM

```typescript
interface JsCircuitConfig {
  maxJwtB64Len: number;
  maxPayloadB64Len: number;
  maxAudLen: number;
  maxExpLen: number;
  maxIssLen: number;
  maxNonceLen: number;
  maxSubLen: number;
  n: number;               // Total number of credential slots
  k: number;               // Threshold (k-of-n)
  treeHeight: number;
  numAudienceLimit: number;
  claims: string[];
  forbiddenString: string;
}
```

### React Native

```typescript
interface CircuitConfig {
  max_jwt_b64_len: number;
  max_payload_b64_len: number;
  max_aud_len: number;
  max_exp_len: number;
  max_iss_len: number;
  max_nonce_len: number;
  max_sub_len: number;
  n: number;
  k: number;
  tree_height: number;
  num_audience_limit: number;
  claims: string[];
  forbidden_string: string;
}
```

### Example Config

```typescript
// Node.js / WASM (camelCase)
const config = {
  maxJwtB64Len: 1024,
  maxPayloadB64Len: 640,
  maxAudLen: 155,
  maxExpLen: 20,
  maxIssLen: 93,
  maxNonceLen: 93,
  maxSubLen: 93,
  n: 6,
  k: 3,
  treeHeight: 4,
  numAudienceLimit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbiddenString: 'forbidden',
};
```

---

## generateHash

Compute a Poseidon hash of one or more field-element strings.

**Input:** Array of hex (`0x...`) or decimal strings.

**Output:** `0x`-prefixed hex string.

### Node.js

```typescript
import { generateHash } from '@baerae/zkap-zkp';

const hash = generateHash(['0x1', '0x2', '0x3']);
// => '0x2b7e15...'
```

### WASM

```typescript
import init, { generateHash } from '@baerae/zkap-zkp-wasm';

await init();
const hash = generateHash(['0x1', '0x2', '0x3']);
```

### React Native

```typescript
import { generateHash } from '@baerae/zkap-zkp-react-native';

const hash = await generateHash(['0x1', '0x2', '0x3']);
```

---

## generateAudHash

Compute per-audience Poseidon hashes and a combined audience-list hash. Used to bind a proof to a set of allowed audiences.

**Input:** `CircuitConfig` + array of audience strings.

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `audHashes` (Node/WASM) / `aud_hashes` (RN) | `string[]` | Per-slot hash (including padding slots, total = `numAudienceLimit`) |
| `hAudList` (Node/WASM) / `h_aud_list` (RN) | `string` | Combined audience-list hash (`0x`-prefixed hex) |

### Node.js

```typescript
import { generateAudHash } from '@baerae/zkap-zkp';

const result = generateAudHash(config, ['client-a', 'client-b']);
console.log(result.hAudList);    // '0x...'
console.log(result.audHashes);   // ['0x...', '0x...', ...]
```

### WASM

```typescript
import init, { generateAudHash } from '@baerae/zkap-zkp-wasm';

await init();
const result = generateAudHash(config, ['client-a', 'client-b']);
```

### React Native

```typescript
import { generateAudHash } from '@baerae/zkap-zkp-react-native';

const result = await generateAudHash(config, ['client-a', 'client-b']);
console.log(result.h_aud_list);  // '0x...'
console.log(result.aud_hashes);  // ['0x...', '0x...', ...]
```

---

## generateLeafHash (Utility)

> **Utility API** -- available for custom integrations. Not used in current production deployments.

Compute the Merkle leaf hash for an issuer + RSA public-key modulus. Used to build the issuer Merkle tree.

**Input:** `CircuitConfig` + issuer URL string + base64-encoded RSA public key modulus.

**Output:** `0x`-prefixed hex string (leaf field element).

### Node.js

```typescript
import { generateLeafHash } from '@baerae/zkap-zkp';

const leaf = generateLeafHash(config, 'https://accounts.google.com', pkModulusB64);
```

### WASM

```typescript
import init, { generateLeafHash } from '@baerae/zkap-zkp-wasm';

await init();
const leaf = generateLeafHash(config, 'https://accounts.google.com', pkModulusB64);
```

### React Native

```typescript
import { generateLeafHash } from '@baerae/zkap-zkp-react-native';

const leaf = await generateLeafHash(config, 'https://accounts.google.com', pkModulusB64);
```

---

## generateAnchor

Generate a Poseidon threshold anchor from JWT credential secrets. The anchor binds a set of credential triples (sub, iss, aud) into a single polynomial commitment.

**Input:** `CircuitConfig` + array of `Secret` objects. The array length must equal `config.n`.

### Secret

```typescript
// Node.js / WASM
interface JsSecret {
  sub: string;
  iss: string;
  aud: string;
}

// React Native (same fields)
interface Secret {
  sub: string;
  iss: string;
  aud: string;
}
```

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `evaluations` | `string[]` | Anchor polynomial evaluation points (`0x`-prefixed hex) |

### Node.js

```typescript
import { generateAnchor } from '@baerae/zkap-zkp';

const secrets = Array.from({ length: config.n }, (_, i) => ({
  sub: `user-${i}`,
  iss: 'https://accounts.google.com',
  aud: 'my-client-id',
}));

const anchor = generateAnchor(config, secrets);
console.log(anchor.evaluations); // ['0x...', '0x...', ...]
```

### WASM

```typescript
import init, { generateAnchor } from '@baerae/zkap-zkp-wasm';

await init();
const anchor = generateAnchor(config, secrets);
```

### React Native

```typescript
import { generateAnchor } from '@baerae/zkap-zkp-react-native';

const anchor = await generateAnchor(config, secrets);
```

---

## prove

Generate Groth16 zero-knowledge proofs. **Not available in WASM.**

Requires a proving key file on disk.

### ProveRequest

| Field | Type | Description |
|-------|------|-------------|
| `pkPath` / `pk_path` | `string` | Absolute path to the proving key file |
| `jwts` | `string[]` | JWT tokens (exactly `k` entries) |
| `pkOps` / `pk_ops` | `string[]` | Base64-encoded RSA public key moduli (one per JWT) |
| `merklePaths` / `merkle_paths` | `string[][]` | Merkle authentication paths (one per JWT) |
| `leafIndices` / `leaf_indices` | `number[]` | Merkle leaf indices (one per JWT) |
| `root` | `string` | Merkle root (hex or decimal field element) |
| `anchorEvals` / `anchor_evals` | `string[]` | Anchor polynomial evaluations (from `generateAnchor`) |
| `hanchor` | `string` | Combined anchor hash |
| `hSignUserOp` / `h_sign_user_op` | `string` | Signed UserOperation hash |
| `random` | `string` | Random blinding value |
| `audHashList` / `aud_hash_list` | `string[]` | Audience hashes (from `generateAudHash`) |

### ProveResult / JsProofOutput

| Field | Type | Description |
|-------|------|-------------|
| `proofs` | `string[][]` | Solidity-compatible proof per JWT: `[ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy]` |
| `sharedInputs` / `shared_inputs` | `string[]` | Public inputs shared across all JWTs (decimal strings) |
| `partialRhsList` / `partial_rhs_list` | `string[]` | `partial_rhs` per JWT (decimal string) |
| `jwtExpList` / `jwt_exp_list` | `string[]` | `jwt_exp` per JWT (decimal string) |

### Node.js

```typescript
import { prove } from '@baerae/zkap-zkp';

const result = prove(config, {
  pkPath: '/path/to/pk.bin',
  jwts: [...],
  pkOps: [...],
  merklePaths: [...],
  leafIndices: [...],
  root: '...',
  anchorEvals: anchor.evaluations,
  hanchor: '...',
  hSignUserOp: '...',
  random: '...',
  audHashList: audResult.audHashes,
});

console.log(result.proofs);        // Solidity-compatible proof arrays
console.log(result.sharedInputs);  // Shared public inputs
```

### React Native

```typescript
import { prove } from '@baerae/zkap-zkp-react-native';

const result = await prove(config, {
  pk_path: '/path/to/pk.bin',
  jwts: [...],
  pk_ops: [...],
  merkle_paths: [...],
  leaf_indices: [...],
  root: '...',
  anchor_evals: anchor.evaluations,
  hanchor: '...',
  h_sign_user_op: '...',
  random: '...',
  aud_hash_list: audResult.aud_hashes,
});
```

---

## Error Handling

All functions throw on invalid input. Common error cases:

| Error | Cause |
|-------|-------|
| `prove() is not supported in WebAssembly` | Calling `prove` from `@baerae/zkap-zkp-wasm` |
| `groth16Setup() is not supported` | `setup` has been removed from all SDK packages (v0.1.2+) |
| `verify() is not supported` | `verify` has been removed from all SDK packages (v0.1.2+) |
