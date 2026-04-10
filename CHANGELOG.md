# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
