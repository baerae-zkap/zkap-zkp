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

### iOS XCFramework (sdk-react-native)

The XCFramework is built by CI (`build-react-native.yml`). To build locally on macOS:

**Prerequisites**

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

**Build**

```bash
bash scripts/build-ios-xcframework.sh
```

Output: `packages/sdk-react-native/ios/ZkapZkp.xcframework/`

After building, run `pod install` in your Expo project to link the framework.

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

Release versions are committed in each publishable `package.json`. To prepare a release,
sync all package versions first:

```bash
node scripts/sync-versions.mjs <version>
# Example: node scripts/sync-versions.mjs 0.2.0
```

This updates the 8 publishable packages and synchronizes the internal package references in
`packages/sdk` and `packages/sdk-node`.

Release rules:

1. Commit the synchronized version changes before tagging.
2. Keep the root [`package-lock.json`](./package-lock.json) committed and up to date only when dependencies change.
3. Publish only through [`.github/workflows/release.yml`](./.github/workflows/release.yml).
4. The workflow validates:
   - all publishable package versions match the tag
   - internal package dependency versions are synchronized
   - each package version is newer than the npm `latest` tag, unless it is the first publish
5. Publish order is fixed:
   - platform packages
   - `@baerae/zkap-zkp-node`
   - `@baerae/zkap-zkp-wasm`
   - `@baerae/zkap-zkp-react-native`
   - `@baerae/zkap-zkp`

Trusted publishing notes:

- After the first manual/bootstrap publish of each package, connect the package to the GitHub Actions trusted publisher on npm.
- Once all 8 packages are linked, release publishing runs token-free through OIDC.
- See [docs/release-runbook.md](./docs/release-runbook.md) for the first-publish sequence and npm setup checklist.

## Commit Messages

Write commit messages in English.
