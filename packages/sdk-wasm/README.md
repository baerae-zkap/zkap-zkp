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

## Input/output contract

Locked by the cross-runtime golden suite (`golden/anchor-vectors.json`) —
identical for `@baerae/zkap-zkp-node`.

| Item | Contract |
|------|----------|
| `secrets` (`{sub, iss, aud}`) | **Raw strings — no quotes.** The SDK wraps each claim in JSON-style `"…"` internally (0.1.5+ contract, `forbidden` padding included). Caller-side quoting double-wraps and silently changes every anchor/audHash value. |
| Padding | **Caller pads.** `generateAnchor` needs exactly `n` secrets; `deriveSelector` needs exactly `k` (padToThree: 1 account → `[s,s,s]`, 2 → `[s1,s2,s1]`, 3 → `[s1,s2,s3]`). The SDK never pads or shuffles. |
| `anchorEvaluations` | Exactly `n − k + 1` entries (4 for 3-of-6), hex (`0x…`) or decimal field-element strings, in on-chain `getAnchor()` order. Caller slices any extra on-chain fields. |
| `deriveSelector` return | `number[]` of length `n`, 0/1 per slot — the **first** slot combination (ascending `C(n,k)` order) whose committed values match the presented secrets in relative order. Permutations are not searched. |
| Errors | Real `Error` instances with a stable `code` property (see below). Message strings are stable for legacy matching, but branch on `code`. |

### Error codes

| `error.code` | Meaning |
|--------------|---------|
| `NO_VALID_SELECTOR` | Selector search exhausted — the presented secret set (identities, quoting, or relative order) does not match the anchor. |
| `DIMENSION_MISMATCH` | Wrong cardinality: secrets ≠ `k`/`n`, or `anchorEvaluations` ≠ `n − k + 1`. |
| `INVALID_INPUT` | A field element, claim value, or argument shape failed parsing/length validation. |
| `UNSUPPORTED_PLATFORM` | The function is not available in this runtime (`prove`/`verify`/`groth16Setup` here). |
| `GenericFailure` | Unclassified internal failure. |
