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

# WASM tests
cd packages/sdk-wasm && wasm-pack test --node
```

## Pull Requests

1. Fork the repository.
2. Create a branch: `git checkout -b feat/your-feature`
3. Run `cargo clippy --workspace -- -D warnings` and fix all warnings.
4. Run tests and ensure they pass.
5. Open a PR targeting the `develop` branch.

## Commit Messages

Write commit messages in English.
