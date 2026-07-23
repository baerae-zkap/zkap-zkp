# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **`deriveSelector` is now available in the react-native runtime** (`@baerae/zkap-zkp-react-native`), closing the last runtime gap (node 0.1.11, wasm 0.1.13): the UniFFI crate exports `derive_selector(config, secrets, anchorEvaluations): number[]` with the same contract — the k-of-n slot selector (0/1 per slot) iff the presented raw secrets, in slot-ascending relative order, occupy some slot combination of the anchor. Wrong-length `anchorEvaluations` is rejected up front as a dimension mismatch (message parity with node/wasm; UniFFI errors carry no `code` field, so match on the stable message text). The facade `react-native` condition now calls the native module instead of throwing `UnsupportedPlatformError`. This enables on-device anchor membership self-checks immediately after anchor construction, which previously required round-tripping through the node or wasm runtime. The golden vectors (`golden/anchor-vectors.json`) are now also executed against the UniFFI surface (`crates/uniffi-bindings/src/anchor_golden_tests.rs`), so node/wasm/react-native contract drift fails `cargo test`.

## [0.1.13] - 2026-07-17

### Added

- **`deriveSelector` is now available in the browser wasm runtime** (`@baerae/zkap-zkp-wasm`), mirroring the Node NAPI binding added in 0.1.11: `deriveSelector(config, secrets, anchorEvaluations): number[]` returns the k-of-n slot selector (0/1 per slot) iff the presented raw secrets — in slot-ascending relative order — occupy some slot combination of the anchor. This enables client-side membership pre-checks against shuffled 3-of-6 anchors whose dummy preimages were discarded at registration. The facade re-exports it on `node`, `node-sync`, and `wasm` conditions; `react-native` throws `UnsupportedPlatformError` (native module does not expose it yet).
- **Machine-readable `error.code` on thrown errors** across `generateHash` / `generateAnchor` / `deriveSelector` / `generateAudHash` / `generateLeafHash` / `prove` in BOTH node and wasm runtimes: `NO_VALID_SELECTOR` (exhausted selector search — the anchor/JWT-set mismatch signal), `DIMENSION_MISMATCH` (secrets ≠ k / n, anchor evaluations ≠ n−k+1), `INVALID_INPUT` (field/claim parse failures, length violations). Unclassified errors keep the previous `GenericFailure` code. **Message strings are unchanged** — existing consumers matching the stable message text ("No valid selector found") keep working; `code` is additive. `prove()` classifies the witness-gen "no valid selector" report the same way, so proof workers can branch on `code` instead of message text.
- **`deriveSelector` rejects a wrong-length `anchorEvaluations` up front** with `DIMENSION_MISMATCH` in both runtimes. The rust core reports that case as an exhausted search ("No valid selector found"), which would mis-signal an identity mismatch.
- **Cross-runtime golden vectors** (`golden/anchor-vectors.json`, regenerate via `scripts/generate-anchor-golden.mjs`): anchor generation for the padToThree shapes (1/2/3 accounts in explicit 6-slot layouts), deriveSelector membership + negative cases (order swap, double quoting, empty identity, poisoned empty-identity anchor), audience hashes, and error codes — executed by both `packages/sdk-node/__test__/anchor-golden.spec.ts` and `packages/sdk-wasm/tests/anchor_golden.rs` so node/wasm contract drift (the 0.1.5-class quoting regression) fails CI.

### Changed

- **wasm: thrown values are now real `Error` instances** (with `message` and `code`) instead of raw strings. `err.message` now works; code that relied on `typeof err === 'string'` or exact `String(err)` equality (now `"Error: <msg>"`) must read `err.message`. The unsupported-platform stubs (`groth16Setup`/`prove`/`verify`) throw `code: 'UNSUPPORTED_PLATFORM'` with unchanged messages.

## [0.1.10] - 2026-06-12

### Fixed

- **React Native: `expo-file-system/legacy` is now imported with a string-literal specifier.** `loadExpoFileSystem` previously called `await import(...)` with a variable specifier, which Metro does not bundle (it only follows static string-literal `import()`/`require()`). The module was therefore omitted from the app bundle and the dynamic import failed at runtime, surfacing the misleading `require expo-file-system. Install it…` error even when `expo-file-system` was installed. The specifier is now inlined as the literal `'expo-file-system/legacy'`. Node/vitest behavior is unchanged. (`packages/sdk/src/react-native.ts`)
- **Build: added an ambient module declaration for `expo-file-system/legacy`.** The literal import above broke the tsup `.d.ts` build with `TS2307` because the SDK does not depend on `expo-file-system`, so TypeScript could not resolve the optional peer's types. A shorthand ambient declaration restores the dts build; the call site already narrows with an `ExpoFileSystem` cast. Type-only — runtime behavior unchanged. (`packages/sdk/src/expo-file-system-legacy.d.ts`)

## [0.1.9] - 2026-06-10

### Changed

- **BREAKING — `@baerae/zkap-zkp/node-sync` now formats the Merkle authentication path inside `prove()`**, matching the async `node` facade and `react-native`. The synchronous facade previously re-exported the native `prove` verbatim, so the on-chain `getMerklePath()` auth path reached the prover unformatted and failed the issuer-key Merkle-membership constraint (`InvalidProveRequest … issuer-key leaf is not a member of merkle_root`) unless the caller reordered it. Synchronous callers now pass the contract path verbatim; the SDK reorders it exactly once via `formatMerklePathForCircuit`. Any caller- or server-side reversal must be removed to avoid a double-reverse (which fails the same constraint). `node-sync` also re-exports `formatMerklePathForCircuit` / `withFormattedMerklePaths` to match `node`, so all proving facades (`node`, `node-sync`, `react-native`) return identical output for identical input.

## [0.1.8] - 2026-06-10

### Added

- **`downloadRelease` now reports progress and supports cancellation.** Callers can pass a progress callback (per-artifact byte progress via `buildArtifactProgress`) and an `AbortSignal`; a cached staged release is validated fully offline against its own `manifest.json` (`isStagedManifestValid` — every artifact's size and content SHA256 must match) instead of requiring a `SHA256SUMS` fetch.
- **`downloadWitnessGen` URL channel.** The witness generator (`witness_gen.wasm` + `witness_gen.json` sidecar) is fetched from witness-gen's own release channel; `prove()` defaults to the witness-gen artifacts co-located with the CRS release when no explicit paths are given.

### Changed

- **BREAKING — `witness_gen.wasm` is now an independent path + sidecar, not read from the signed CRS manifest.** zkap-circuit Phase 2 removed `manifest.artifacts.witness_gen`, so the app now supplies `witness_gen.wasm` + a `witness_gen.json` sidecar as separate local paths. Integrity (sha256) and compatibility (`compatible_ar1cs_blake3` vs the CRS `ar1cs_blake3`) are verified against the sidecar, fail-closed. `prepareProver(manifestDir, witnessGenPath, witnessGenSidecarPath)` (was 1-arg); `ProofRequest` / `JsProofRequest` / uniffi `ZkapProofRequest` gain required `witnessGenPath` + `witnessGenSidecarPath`. No back-compat window. Builds against the published `zkap-service` v0.1.1-rc.3 (sidecar schema + `load_witness_gen`).
- **BREAKING — the Merkle authentication path is now formatted inside `prove()`.** Callers pass the on-chain auth path verbatim; the SDK reorders it internally (the previous caller-side reversal must be removed to avoid a double-reverse).

## [0.1.7] - 2026-06-01

### Fixed

- **`@baerae/zkap-zkp-react-native` UniFFI bindings can no longer drift from the shipped native library.** The generated TypeScript/C++ bindings (`src/generated/`, `cpp/generated/`) are no longer committed; they are regenerated from the Rust crate at `prepack` (via `scripts/generate-rn-bindings.mjs`, which runs `uniffi-bindgen-react-native` from the crate directory) on every publish, so their embedded FFI checksums always match the bundled `ZkapZkp.xcframework`. In `0.1.6` the committed bindings had drifted: the P2 zkap-service façade changed the `prove` interface but the bindings were never regenerated, so the published TypeScript expected `prove` checksum `35511` while the shipped xcframework returned `59563` — breaking every on-device `prove()` with an `ApiChecksumMismatch` ("incompatible Uniffi versions") error.

### Changed

- **`@baerae/zkap-zkp-react-native` WKWebView witness runner now surfaces `error.message`.** The inline `fail()` handler posts `error.message` (in addition to `error.stack`) instead of only `error.stack`, so wasm witness-synthesis rejections report the actual constraint detail rather than just a stack trace.

## [0.1.6] - 2026-05-29

### Removed (BREAKING)

- **Dropped the SDK-enforced zkap-circuit commit pin.** Removed the `ZKAP_CIRCUIT_COMMIT` constant (TS + Rust), the `assertManifestCircuitCommit` / `validate_manifest_circuit_commit` checks, and the `expectedCircuitCommit` / `allowCircuitCommitMismatch` options on `downloadRelease` / `loadRelease`. The SDK no longer compares a release's `manifest.build.circuit_commit` against a hardcoded revision. Release artifacts are still integrity-checked against `<shape>-SHA256SUMS` (and the optional `expectedReleaseSha` pin); ensuring the served circuit release is compatible with the SDK is now the caller's responsibility.

### Fixed

- **`@baerae/zkap-zkp-react-native` now pins `uniffi-bindgen-react-native` to exactly `0.31.0-2`** (was `^0.31.0-2`). The shipped C++ bindings (`cpp/generated/zkap_uniffi_bindings.cpp`) call the `string_to_arraybuffer` / `arraybuffer_to_string` ubrn runtime symbols, which were renamed to `string_to_buffer` / `string_from_buffer` in `0.31.0-3`. The caret range allowed consumer fresh-installs to resolve `0.31.0-3`, breaking the Android/iOS native compile (and `android/CMakeLists.txt`'s `require.resolve('uniffi-bindgen-react-native/package.json')`, since `0.31.0-3` no longer exports `./package.json`). The monorepo lockfile already pinned `0.31.0-2`, so the break only surfaced for downstream consumers.

## [0.1.5] - 2026-05-29

The largest release since `0.1.0`: a unified multi-runtime facade, a native UniFFI/JSI React Native package, a prepared/native proving core, and release-bundle download & staging helpers.

### Added

- **Multi-runtime facade `@baerae/zkap-zkp`.** Public facade with `node`, `node-sync`, browser `wasm`, and `react-native` export conditions and a uniform Promise-based API. Re-exports `generateHash`, `generateLeafHash`, `generateAudHash`, `generateAnchor`, `prepareProver`, `prove`, `verify`, `downloadRelease`, `loadRelease`, `loadCircuitConfig`, `normalizeCircuitConfig`, `initZkap`, and `ZKAP_CIRCUIT_COMMIT`. Adds shared release-manifest validation, normalized camelCase `CircuitConfig` types, and typed error classes.
- **Native React Native package (`@baerae/zkap-zkp-react-native`).** Replaces the Expo module wrapper with a UniFFI/JSI binding: Android (Kotlin module/package, CMake, generated UniFFI C++/TS bindings) and iOS (podspec, Objective-C++ bridge, WKWebView witness-bridge, XCFramework build script) packaging, plus native artifact validation/rebuild scripts.
- **Prepared / native proving core.** New `crates/prover` crate stages flat zkap-circuit release bundles into manifest-compatible directories (`load_release` / `LoadedRelease`, `ReleaseError`). `prepareProver(manifestDir)` (`sdk-node`) pre-loads the artifact set so later `prove()` calls skip cold setup; `prove()` / `verify()` run through the `ark-ar1cs` / `zkap-service` `ArtifactSet`.
- **`downloadRelease({ baseUrl, shape, ... })`** (`sdk-node`, `sdk-react-native`): downloads a zkap-circuit flat release bundle from static hosting and stages it as a local `manifestDir`. Supports `expectedReleaseSha` pinning, cache reuse, progress callbacks, and custom networking through `fetch`.
- **`loadRelease({ releaseDir, shape })`** (`sdk-node`, re-exported from `@baerae/zkap-zkp`): ingests zkap-circuit's flat prefixed release bundle (e.g. `1-of-1-pk.bin`, `1-of-1-manifest.json`, `1-of-1-SHA256SUMS`) and produces a SHA-verified unprefixed staged directory under `os.tmpdir()/zkap-release-<sha>-<shape>/`. Output: `{ stagedDir, manifestJson, shape, releaseSha }`. Idempotent (warm-cache re-call < 2s), concurrent-safe (`fs2` exclusive lock + atomic rename). Pass `stagedDir` as `request.manifestDir` to `prove()` / `verify()`. Non-breaking — existing `manifestDir` API unchanged.
- **`loadCircuitConfig(manifestDir)` / `normalizeCircuitConfig(input)`**: read release `config.json`, verify it against `manifest.json`, and return the public facade camelCase `CircuitConfig`.

### Changed

- **`@baerae/zkap-zkp` no longer hard-depends on every runtime binding.** The compatibility facade now declares the runtime packages as optional peers, so installing the facade does not force Node, WebAssembly, and React Native bindings into every application. Consumers that use the facade must install `@baerae/zkap-zkp` plus exactly one matching runtime package.
- Repository URLs updated after the GitHub rename to `zkap-zkp-sdk`. README and `docs/` rewritten to document the facade model and release-backed SDK usage.

### Fixed

- **`verify` is now re-exported through `@baerae/zkap-zkp` facade.** Previously defined in `@baerae/zkap-zkp-node`'s `index.d.ts` but never re-exported through the public facade; this blocked consumers of the ADR-003 facade-only convention (e.g. `zkap-zkp-testbed/node-harness/`) from calling `verify()` without violating the lint rule.
- Release/publish ordering: the npm upgrade step is delayed until the release publish stage to avoid bootstrapping against not-yet-published versions.

### Removed

- `examples/browser` and `examples/node` directories removed from the repository.
- Expo module wiring (`expo-module.config.json`) removed from the React Native package as part of the native rewrite.

### CI / Tooling

- Packed consumer smoke tests (`scripts/smoke-packed-consumers.mjs`) and hardened release bootstrap validation. New verification scripts: `verify-node-platform-packages.mjs`, `check-rn-native-artifacts.mjs`, `check-rn-ios-runtime.mjs`.

### Notes

- **npm package names are unchanged from `0.1.4`.** A `-sdk-` infix rename was introduced mid-cycle and then reverted: the GitHub repository is `zkap-zkp-sdk`, but the published npm packages keep their original names (`@baerae/zkap-zkp-node`, `-wasm`, `-react-native`, and the `node-*` platform packages) so existing installs resolve correctly.
- **React Native is now a native module.** The UniFFI/JSI package requires a native rebuild (autolinking + pod install / Gradle); it is no longer a pure Expo JS module. Device builds and real-CRS proving were not exercised in CI.
- **Host limitation: `node-harness` `file:` install supports darwin-arm64 only in this iteration.** The `overrides` block in `zkap-zkp-testbed/node-harness/package.json` pins the napi platform package for darwin-arm64; other host arches (darwin-x64, linux-x64-gnu, linux-x64-musl) require additional overrides — tracked as a follow-up.

## [0.1.4] - 2026-04-15

A maintenance and documentation release: trimmed the dependency surface and shipped the first public, package-user-facing docs. No hashing/proving API changes.

### Added

- **`docs/API_REFERENCE.md`** — full type signatures, a platform support matrix, and code examples for all three packages.
- **`docs/REACT_NATIVE_GUIDE.md`** — installation, setup, and usage instructions for the React Native package.

### Changed

- README capability matrix: added the Core API / Utility API distinction, a React Native column, a naming-convention table, and a proving-key section. `CONTRIBUTING.md` no longer references the internal release-runbook path.

### Removed

- **`artifact-manager`** removed from `@baerae/zkap-zkp` (`sdk`) and `@baerae/zkap-zkp-react-native` (`sdk-react-native`).
- **`expo-crypto` and `expo-file-system`** removed from the React Native package's `peerDependencies`.
- Internal `docs/release-runbook.md` removed from the public `docs/` directory.

### Fixed

- **`@baerae/zkap-zkp` (`sdk`) test command.** `artifact-manager.spec.ts` was the only test in the facade package; after its removal `ava` failed with "Couldn't find any files to test". The test script is now a no-op (`sdk` is a pure re-export package). Unused `ava` and `swc` devDependencies were dropped.

## [0.1.3] - 2026-04-14

React Native UniFFI build and CI fixes following the `0.1.2` UniFFI rewrite.

### Fixed

- **(uniffi)** add mimalloc global allocator and fix iOS podspec paths.
- **(ios)** use a consistent binary name for the XCFramework simulator slice; iOS build script now uses the `zkap-uniffi-bindings` crate.
- **(ci)** add `CC` / `AR` env vars for Android NDK cross-compilation.
- **(sdk-react-native)** fix the Kotlin `message` property conflict in `ZkapException`.

## [0.1.2] - 2026-04-10

### Breaking Changes

- **`JsProofRequest` field split** (`sdk-node`, `sdk-wasm`, `sdk-react-native`): `anchor: string[]` removed; replaced by `anchorEvals: string[]` (polynomial evaluations) and `hanchor: string` (anchor chain hash)
- **`JsProofRequest` field rename** (`sdk-node`, `sdk-wasm`, `sdk-react-native`): `audList: string[]` renamed to `audHashList: string[]`; values must now be pre-hashed via `generateAudHash()`

### Removed

- `groth16Setup()` removed from `sdk-node` public API
- `verify()` removed from `sdk-node` public API
- `JsSetupOutput` type removed from `sdk-node`

### Added

- **React Native UniFFI support**: `sdk-react-native` rewritten using [UniFFI](https://mozilla.github.io/uniffi-rs/) with full Android (Kotlin) and iOS (Swift + XCFramework) bindings

### Changed

- **`sdk-wasm` default build target**: changed from `bundler` to `web`; use `npm run build:bundler` for the previous bundler target
- **`generateHash`, `generateLeafHash`, `generateAudHash`**: string encoding now handled inside `zkap-service`; external behavior is unchanged

## [0.1.1] - 2026-04-09

### Title: Solidity-Ready Proof Output

### Changed
- **`prove()` return format** (`sdk-node`, `sdk-react-native`): replaced binary-serialized proof and hex-encoded public inputs with Solidity-compatible decimal string arrays. The proof is now an 8-element array `[ax, ay, bx_c1, bx_c0, by_c1, by_c0, cx, cy]` and public inputs are split into three explicit fields: `sharedInputs`, `partialRhsList`, and `jwtExpList`

### Fixed
- **Zero field element handling**: `proof_to_solidity` now returns `"0"` for zero field elements, matching canonical Solidity trait behavior in zkap-circuit
- **Shared public inputs validation**: `split_public_inputs` now validates that shared indices `[0,1,2,3,6,7]` are identical across all JWT rows, returning an explicit error instead of silently producing incorrect values

### Security
- Pin `cargo-bins/cargo-binstall` to commit SHA (v1.17.9) in CI workflows — previously used `@main` branch reference
- Pin `addnab/docker-run-action` to commit SHA in CI workflows — previously used mutable `@v3` tag

## [0.1.0] - 2026-04-07

### Added
- `@baerae/zkap-zkp` — Node.js facade with full API (hash, anchor, prove, verify)
- `@baerae/zkap-zkp-node` — napi-rs native bindings (darwin-x64, darwin-arm64, linux-x64-gnu, linux-x64-musl)
- `@baerae/zkap-zkp-wasm` — WebAssembly bindings (hash functions only)
- `artifact-manager` — On-demand PK download from S3 with SHA256 verification and HTTP resume
- GitHub Actions workflows for multi-platform build and npm publish
