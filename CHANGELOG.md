# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- **`downloadRelease({ baseUrl, shape, ... })`** (`@baerae/zkap-zkp`): downloads a zkap-circuit flat release bundle from static hosting and stages it as a local `manifestDir` for Node.js and React Native. Supports `expectedReleaseSha` pinning, cache reuse, progress callbacks, and test/custom networking through `fetch`.
- **`loadCircuitConfig(manifestDir)` / `normalizeCircuitConfig(input)`**: reads release `config.json`, verifies it against `manifest.json`, and returns the public facade camelCase `CircuitConfig`; `normalizeCircuitConfig` is available in Node.js, React Native, and WASM.

## [0.1.5] - 2026-05-20

### Added

- **`loadRelease({ releaseDir, shape })`** (`sdk-node`, re-exported from `@baerae/zkap-zkp`): ingests zkap-circuit's flat prefixed release bundle (e.g. `1-of-1-pk.bin`, `1-of-1-manifest.json`, `1-of-1-SHA256SUMS`) and produces a SHA-verified unprefixed staged directory under `os.tmpdir()/zkap-release-<sha>-<shape>/`. Output: `{ stagedDir, manifestJson, shape, releaseSha }`. Idempotent (warm-cache re-call < 2s), concurrent-safe (`fs2` exclusive lock + atomic rename). Pass `stagedDir` as `request.manifestDir` to `prove()` / `verify()`. Non-breaking — existing `manifestDir` API unchanged.

### Fixed

- **`verify` is now re-exported through `@baerae/zkap-zkp` facade.** Previously defined in `@baerae/zkap-zkp-node`'s `index.d.ts` but never re-exported through the public facade; this blocked consumers of the ADR-003 facade-only convention (e.g. `zkap-zkp-testbed/node-harness/`) from calling `verify()` without violating the lint rule.

### Notes

- **`sdk-wasm` + `sdk-react-native` version-only bump.** No source or native artifact changes in these packages. Version moved from `0.1.4` to `0.1.5` to preserve the synchronized-version invariant enforced by `scripts/check-release-packages.mjs`.
- **Host limitation: `node-harness` `file:` install supports darwin-arm64 only in this iteration.** The `overrides` block in `zkap-zkp-testbed/node-harness/package.json` pins the napi platform package for darwin-arm64; other host arches (darwin-x64, linux-x64-gnu, linux-x64-musl) require additional overrides — tracked as a follow-up.

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
