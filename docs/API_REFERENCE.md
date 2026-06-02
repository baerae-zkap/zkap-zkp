# API Reference

Public API for the `@baerae/zkap-zkp` compatibility facade. Install it with the
matching runtime package for your environment:

```bash
# Node.js
npm install @baerae/zkap-zkp @baerae/zkap-zkp-node

# Browser/WebAssembly
npm install @baerae/zkap-zkp @baerae/zkap-zkp-wasm

# React Native
npx expo install @baerae/zkap-zkp @baerae/zkap-zkp-react-native
```

Do not install `@baerae/zkap-zkp` by itself unless another dependency already
provides the matching runtime package. The facade declares runtime packages as
optional peers so it does not force every environment to install Node,
WebAssembly, and React Native bindings.

The direct runtime packages keep their runtime-native API shapes. The facade
normalizes those APIs to Promise-based functions, camelCase config, and shared
helpers such as `downloadRelease()`.

## Platform Support

### Core API

Functions actively used in production integrations.

| Function | Node.js | WASM | React Native | Notes |
|----------|---------|------|--------------|-------|
| `generateHash` | async | async | async | Poseidon hash |
| `generateAudHash` | async | async | async | Audience hash |
| `generateAnchor` | async | async | async | Threshold anchor |
| `prove` | async | -- | async | Requires manifest-backed CRS/proving bundle |
| `downloadRelease` | async | -- | async | Downloads/stages a flat release bundle; progress + `AbortSignal` |
| `getCachedReleaseInfo` | async | -- | async | Read-only, offline check of a staged release |
| `loadCircuitConfig` | async | -- | async | Reads release `config.json` as camelCase config |

### Utility API

Available for custom integrations. Not used in current production deployments.

| Function | Node.js | WASM | React Native | Notes |
|----------|---------|------|--------------|-------|
| `generateLeafHash` | async | async | async | Merkle leaf hash |
| `normalizeCircuitConfig` | sync | sync | sync | Converts snake_case or camelCase config to facade camelCase |

> Trusted setup is not included in the public facade. `verify` is available in Node.js and throws `UnsupportedPlatformError` in WASM and React Native.

> WASM cannot run `prove` due to memory constraints. Calling it throws an error with a message directing you to Node.js or React Native.

## Naming Conventions

The compatibility facade uses **camelCase** config fields in every runtime.
The direct React Native runtime package keeps its historical snake_case input
shape.

| Node.js / WASM | React Native |
|-----------------|--------------|
| `maxJwtB64Len` | `max_jwt_b64_len` |
| `maxPayloadB64Len` | `max_payload_b64_len` |
| `treeHeight` | `tree_height` |
| `numAudienceLimit` | `num_audience_limit` |
| `forbiddenString` | `forbidden_string` |

All other field names (`n`, `k`, `claims`) are identical across platforms.

The release bundle's `config.json` is produced by zkap-circuit with snake_case
fields. Use `loadCircuitConfig(manifestDir)` after `downloadRelease()` or
`loadRelease()` instead of duplicating config constants in application code.

---

## CircuitConfig

Circuit parameters required by most functions. The config must match the configuration used during trusted setup (CRS generation).

### Public facade

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

### Direct React Native package

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
import { generateHash } from '@baerae/zkap-zkp/node';

const hash = await generateHash(['0x1', '0x2', '0x3']);
// => '0x2b7e15...'
```

### WASM

```typescript
import { initZkap, generateHash } from '@baerae/zkap-zkp/wasm';

await initZkap();
const hash = await generateHash(['0x1', '0x2', '0x3']);
```

### React Native

```typescript
import { generateHash } from '@baerae/zkap-zkp/react-native';

const hash = await generateHash(['0x1', '0x2', '0x3']);
```

---

## generateAudHash

Compute per-audience Poseidon hashes and a combined audience-list hash. Used to bind a proof to a set of allowed audiences.

**Input:** `CircuitConfig` + array of audience strings.

**Output:**

| Field | Type | Description |
|-------|------|-------------|
| `audHashes` | `string[]` | Per-slot hash (including padding slots, total = `numAudienceLimit`) |
| `hAudList` | `string` | Combined audience-list hash (`0x`-prefixed hex) |

### Node.js

```typescript
import { generateAudHash } from '@baerae/zkap-zkp/node';

const result = await generateAudHash(config, ['client-a', 'client-b']);
console.log(result.hAudList);    // '0x...'
console.log(result.audHashes);   // ['0x...', '0x...', ...]
```

### WASM

```typescript
import { initZkap, generateAudHash } from '@baerae/zkap-zkp/wasm';

await initZkap();
const result = await generateAudHash(config, ['client-a', 'client-b']);
```

### React Native

```typescript
import { generateAudHash } from '@baerae/zkap-zkp/react-native';

const result = await generateAudHash(config, ['client-a', 'client-b']);
console.log(result.hAudList);    // '0x...'
console.log(result.audHashes);   // ['0x...', '0x...', ...]
```

---

## generateLeafHash (Utility)

> **Utility API** -- available for custom integrations. Not used in current production deployments.

Compute the Merkle leaf hash for an issuer + RSA public-key modulus. Used to build the issuer Merkle tree.

**Input:** `CircuitConfig` + issuer URL string + base64-encoded RSA public key modulus.

**Output:** `0x`-prefixed hex string (leaf field element).

### Node.js

```typescript
import { generateLeafHash } from '@baerae/zkap-zkp/node';

const leaf = await generateLeafHash(config, 'https://accounts.google.com', pkModulusB64);
```

### WASM

```typescript
import { initZkap, generateLeafHash } from '@baerae/zkap-zkp/wasm';

await initZkap();
const leaf = await generateLeafHash(config, 'https://accounts.google.com', pkModulusB64);
```

### React Native

```typescript
import { generateLeafHash } from '@baerae/zkap-zkp/react-native';

const leaf = await generateLeafHash(config, 'https://accounts.google.com', pkModulusB64);
```

---

## generateAnchor

Generate a Poseidon threshold anchor from JWT credential secrets. The anchor binds a set of credential triples (sub, iss, aud) into a single polynomial commitment.

**Input:** `CircuitConfig` + array of `Secret` objects. The array length must equal `config.n`.

### Secret

```typescript
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
import { generateAnchor } from '@baerae/zkap-zkp/node';

const secrets = Array.from({ length: config.n }, (_, i) => ({
  sub: `user-${i}`,
  iss: 'https://accounts.google.com',
  aud: 'my-client-id',
}));

const anchor = await generateAnchor(config, secrets);
console.log(anchor.evaluations); // ['0x...', '0x...', ...]
```

### WASM

```typescript
import { initZkap, generateAnchor } from '@baerae/zkap-zkp/wasm';

await initZkap();
const anchor = await generateAnchor(config, secrets);
```

### React Native

```typescript
import { generateAnchor } from '@baerae/zkap-zkp/react-native';

const anchor = await generateAnchor(config, secrets);
```

---

## downloadRelease

Download a zkap-circuit flat release bundle and stage it as a local
manifest-backed directory. Available in Node.js and React Native. Not available
in browser/WASM because browsers cannot expose a native filesystem path to
`prove()`.

### Remote Layout

```text
<baseUrl>/
  3-of-3-manifest.json
  3-of-3-circuit.ar1cs
  3-of-3-pk.bin
  3-of-3-vk.bin
  3-of-3-pvk.bin
  3-of-3-Groth16Verifier.sol
  3-of-3-config.json
  3-of-3-SHA256SUMS
  witness_gen.wasm
```

### Input

```typescript
interface DownloadReleaseOpts {
  baseUrl: string;
  shape: '1-of-1' | '3-of-3' | string;
  cacheDir?: string;
  expectedReleaseSha?: string;
  force?: boolean;
  fetch?: typeof fetch;
  onProgress?: (progress: DownloadReleaseProgress) => void;
  signal?: AbortSignal; // cancel an in-flight download; partial files are removed
}
```

`expectedReleaseSha` is optional but recommended in production. It pins the
first 16 hex chars of SHA256 of `<shape>-SHA256SUMS`.
Custom shape strings may contain only letters, numbers, dots, underscores, and
hyphens.

Passing an `AbortSignal` lets you cancel a large download (for example when the
user leaves the screen). On abort the promise rejects with an `AbortError`, the
staging temp directory is removed, and any already-completed staged release is
left intact.

### Progress

`onProgress` receives a `DownloadReleaseProgress` for each metadata, per-artifact,
staging, and completion step.

```typescript
interface DownloadReleaseProgress {
  phase: 'metadata' | 'artifact' | 'stage' | 'done';
  artifact?: string;
  // Per-artifact progress.
  artifactLoadedBytes?: number;
  artifactTotalBytes?: number;
  // Whole-release progress (preferred for a single download bar).
  releaseLoadedBytes?: number;
  releaseTotalBytes?: number;
  percent?: number; // [0, 1], present only when releaseTotalBytes is known
  completedArtifacts?: number;
  totalArtifacts?: number;
  // Deprecated: artifact-scoped aliases of artifactLoadedBytes/artifactTotalBytes.
  loadedBytes?: number;
  totalBytes?: number;
}
```

> **Do not show `loadedBytes`/`totalBytes` as overall download progress.** They
> are per-artifact and reset on every file, so a UI built on them appears to
> finish and restart for each artifact. For a single overall bar use
> `percent`, or `releaseLoadedBytes / releaseTotalBytes`. The deprecated
> `loadedBytes`/`totalBytes` remain only for backwards compatibility and mirror
> `artifactLoadedBytes`/`artifactTotalBytes`.

`releaseTotalBytes` is the sum of the manifest artifact sizes (excluding the tiny
`manifest.json`), so it is known from the first artifact onward and is suitable
for a "downloading ~N MB" prompt. React Native emits progress in real time as
each artifact streams (via `expo-file-system`'s resumable downloader), not just
once per file.

### Integrity

| Step | Node.js | React Native |
|------|---------|--------------|
| `<shape>-SHA256SUMS` pin | `expectedReleaseSha` (optional) | `expectedReleaseSha` (optional) |
| `manifest.json` / `config.json` | SHA256 verified | SHA256 verified |
| Large artifacts (`pk.bin`, `circuit.ar1cs`, ...) | content SHA256 streamed and verified before staging | size checked against the manifest during download |
| Before `prove()` | n/a | native `ArtifactSet`/witness path re-applies the manifest SHA256 gate |

React Native does not stream the multi-hundred-MB artifacts through a JavaScript
SHA256 hash; doing so on-device is prohibitively slow and memory-heavy. Content
integrity for those artifacts is enforced natively just before proving, so a
corrupted `pk.bin` fails at `prove()` rather than at download time.

### Output

Same shape as `loadRelease()`:

| Field | Type | Description |
|-------|------|-------------|
| `stagedDir` | `string` | Local manifest directory to pass as `manifestDir` |
| `manifestJson` | `string` | Raw downloaded manifest JSON |
| `shape` | `string` | Echoed release shape |
| `releaseSha` | `string` | First 16 hex chars of SHA256 of `<shape>-SHA256SUMS` |

### Example

```typescript
import { downloadRelease, loadCircuitConfig, prove } from '@baerae/zkap-zkp/node';

const release = await downloadRelease({
  baseUrl: 'https://static.example.com/zkap/releases/v0.1.5',
  shape: '3-of-3',
  expectedReleaseSha: '50aaaa8fe35fc261',
});
const config = await loadCircuitConfig(release.stagedDir);
const result = await prove(config, {
  ...request,
  manifestDir: release.stagedDir,
});
```

The facade's React Native export uses `expo-file-system` for filesystem access. Install it with
`npx expo install expo-file-system` when using `downloadRelease()` or
`loadCircuitConfig()` in a mobile app.

---

## getCachedReleaseInfo

Read-only check of whether a release is already staged, without any network
request. Use it to skip the consent/download screen when the proving bundle is
already present. Available in Node.js and React Native.

### Input

```typescript
interface GetCachedReleaseInfoOpts {
  cacheDir?: string;          // defaults to os.tmpdir() (Node) / app cache (RN)
  shape: '1-of-1' | '3-of-3' | string;
  expectedReleaseSha: string; // pins which staged directory to inspect, offline
}
```

### Output

```typescript
interface CachedReleaseInfo {
  exists: boolean;     // a staged directory for this (releaseSha, shape) exists
  valid: boolean;      // it passes integrity checks and is usable by prove()
  stagedDir?: string;  // present when exists is true
  releaseSha?: string;
  totalBytes?: number; // sum of manifest artifact sizes, when known
}
```

`expectedReleaseSha` is required because the staged directory name encodes the
release SHA, so the lookup needs it to find the directory without downloading
`<shape>-SHA256SUMS`. Validation is performed against the staged `manifest.json`:
Node re-verifies each artifact's content SHA256; React Native verifies each
artifact's size (matching `downloadRelease()`).

### Example

```typescript
import { getCachedReleaseInfo, downloadRelease } from '@baerae/zkap-zkp/react-native';

const cached = await getCachedReleaseInfo({
  shape: '3-of-3',
  expectedReleaseSha: '50aaaa8fe35fc261',
});

if (!cached.valid) {
  // Show the "download ~{cached.totalBytes ?? estimate} MB over Wi-Fi" prompt,
  // then download with progress + cancellation.
  await downloadRelease({ baseUrl, shape: '3-of-3', expectedReleaseSha: '50aaaa8fe35fc261', onProgress });
}
```

---

## loadCircuitConfig / normalizeCircuitConfig

`loadCircuitConfig(manifestDir)` reads `config.json` from a staged release
directory, verifies it against `manifest.json`, and returns the public facade
camelCase `CircuitConfig`.

`normalizeCircuitConfig(input)` performs only the shape conversion/validation
and is available in every runtime.

```typescript
import { loadCircuitConfig, normalizeCircuitConfig } from '@baerae/zkap-zkp/node';

const config = await loadCircuitConfig(release.stagedDir);
const sameShape = normalizeCircuitConfig({
  max_jwt_b64_len: 1024,
  max_payload_b64_len: 896,
  max_aud_len: 155,
  max_exp_len: 20,
  max_iss_len: 93,
  max_nonce_len: 93,
  max_sub_len: 93,
  n: 3,
  k: 3,
  tree_height: 15,
  num_audience_limit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbidden_string: 'forbidden',
});
```

---

## prove

Generate Groth16 zero-knowledge proofs. **Not available in WASM.**

Requires a manifest-backed CRS/proving bundle on disk.

### ProveRequest

| Field | Type | Description |
|-------|------|-------------|
| `manifestDir` | `string` | Directory containing `manifest.json` and CRS artifacts |
| `credentials` | `ProveCredential[]` | JWT credentials (exactly `k` entries) |
| `merkleRoot` | `string` | Merkle root (hex or decimal field element) |
| `anchor` | `string[]` | Anchor polynomial evaluations (from `generateAnchor`) |
| `hSignUserOp` | `string` | Signed UserOperation hash |
| `random` | `string` | Random blinding value |

### ProveResult / JsProofOutput

| Field | Type | Description |
|-------|------|-------------|
| `proofs` | `string[][]` | Solidity-compatible proof per JWT: `[ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy]` |
| `sharedInputs` | `string[]` | Public inputs shared across all JWTs (decimal strings) |
| `partialRhsList` | `string[]` | `partial_rhs` per JWT (decimal string) |
| `jwtExpList` | `string[]` | `jwt_exp` per JWT (decimal string) |

### Node.js

```typescript
import { prove } from '@baerae/zkap-zkp/node';

const result = await prove(config, {
  manifestDir: '/path/to/bundle',
  credentials: [...],
  merkleRoot: '...',
  anchor: anchor.evaluations,
  hSignUserOp: '...',
  random: '...',
});

console.log(result.proofs);        // Solidity-compatible proof arrays
console.log(result.sharedInputs);  // Shared public inputs
```

### React Native

```typescript
import { prove } from '@baerae/zkap-zkp/react-native';

const result = await prove(config, {
  manifestDir: '/path/to/bundle',
  credentials: [...],
  merkleRoot: '...',
  anchor: anchor.evaluations,
  hSignUserOp: '...',
  random: '...',
});
```

---

## Error Handling

All functions throw on invalid input. Common error cases:

| Error | Cause |
|-------|-------|
| `UnsupportedPlatformError` for `prove` | Calling `prove` in WebAssembly |
| `UnsupportedPlatformError` for `downloadRelease` | Calling `downloadRelease` in WebAssembly |
| `UnsupportedPlatformError` for `verify` | Calling `verify` outside Node.js |
| `release SHA mismatch` | `expectedReleaseSha` does not match downloaded `<shape>-SHA256SUMS` |
| `config.json SHA256 mismatch` | `config.json` no longer matches `manifest.json` |
| `AbortError` from `downloadRelease` | The supplied `signal` was aborted; partial staging is cleaned up |
| `SHA256 mismatch` / `invalid size` from `downloadRelease` | A downloaded artifact failed verification (Node: content SHA256; React Native: size) |
