# Contributing

## Prerequisites

- Rust (stable) — https://rustup.rs
- Node.js 18+
- wasm-pack — `cargo install wasm-pack`
- `@napi-rs/cli` — `npm install -g @napi-rs/cli`

## Building

```bash
# Node.js native bindings
cd packages/sdk-node && npm run build

# WebAssembly bindings
cd packages/sdk-wasm && npm run build
```

## Testing

```bash
# Rust tests
cargo test

# Node.js tests (sdk-node)
cd packages/sdk-node && npm test

# TypeScript facade tests (sdk)
cd packages/sdk && npm test

# WASM tests
cd packages/sdk-wasm && wasm-pack test --node
```

## Pull Requests

1. Fork the repository.
2. Create a branch: `git checkout -b feat/your-feature`
3. Run `cargo clippy --workspace -- -D warnings` and fix all warnings.
4. Run `cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2025-0055` and verify no new advisories.
5. Run tests and ensure they pass.
6. Open a PR targeting the `develop` branch.

## Release

Version numbers are synchronized across all packages by running:

```bash
node scripts/sync-versions.mjs <version>
# Example: node scripts/sync-versions.mjs 0.2.0
```

This updates `version` in all 7 `package.json` files and syncs `optionalDependencies` in
`packages/sdk-node`. Actual publishing is triggered by pushing a `v*` tag, which runs
`.github/workflows/release.yml`.

## Commit Messages

Write commit messages in English.
