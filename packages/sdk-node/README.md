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

## Input/output contract

Locked by the cross-runtime golden suite (`golden/anchor-vectors.json`) —
identical for `@baerae/zkap-zkp-wasm`.

| Item | Contract |
|------|----------|
| `secrets` (`{sub, iss, aud}`) | **Raw strings — no quotes.** The SDK wraps each claim in JSON-style `"…"` internally (0.1.5+ contract, `forbidden` padding included). Caller-side quoting double-wraps and silently changes every anchor/audHash value. |
| Padding | **Caller pads.** `generateAnchor` needs exactly `n` secrets; `deriveSelector` needs exactly `k` (padToThree: 1 account → `[s,s,s]`, 2 → `[s1,s2,s1]`, 3 → `[s1,s2,s3]`). The SDK never pads or shuffles. |
| `anchorEvaluations` | Exactly `n − k + 1` entries (4 for 3-of-6), hex (`0x…`) or decimal field-element strings, in on-chain `getAnchor()` order. Caller slices any extra on-chain fields. |
| `deriveSelector` return | `number[]` of length `n`, 0/1 per slot — the **first** slot combination (ascending `C(n,k)` order) whose committed values match the presented secrets in relative order. Permutations are not searched. |
| Errors | Thrown errors carry a stable `code` property: `NO_VALID_SELECTOR` (search exhausted — anchor/secret-set mismatch), `DIMENSION_MISMATCH` (secrets ≠ `k`/`n`, anchor ≠ `n−k+1`), `INVALID_INPUT` (parse/length violations), `GenericFailure` (unclassified). Message strings are stable for legacy matching (`"No valid selector found"`), but branch on `code`. `prove()` classifies the witness-gen "no valid selector" report the same way. |
