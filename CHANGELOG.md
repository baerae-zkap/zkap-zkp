# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] - 2026-04-07

### Added
- `@baerae/zkap-zkp` — Node.js facade with full API (hash, anchor, prove, verify)
- `@baerae/zkap-zkp-node` — napi-rs native bindings (darwin-x64, darwin-arm64, linux-x64-gnu, linux-x64-musl)
- `@baerae/zkap-zkp-wasm` — WebAssembly bindings (hash functions only)
- `artifact-manager` — On-demand PK download from S3 with SHA256 verification and HTTP resume
- GitHub Actions workflows for multi-platform build and npm publish
