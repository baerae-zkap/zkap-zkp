# Release Runbook

## Standard release flow

1. Run `node scripts/sync-versions.mjs <version>`.
2. Review the version changes across:
   - `packages/sdk/package.json`
   - `packages/sdk-node/package.json`
   - `packages/sdk-wasm/package.json`
   - `packages/sdk-react-native/package.json`
   - `platform-packages/node-*/package.json`
3. Commit the version bump.
4. Push tag `v<version>`.
5. Let [`.github/workflows/release.yml`](../.github/workflows/release.yml) validate versions, run tests, run `npm publish --dry-run`, and publish to npm through OIDC.

## First publish bootstrap

Trusted publishing must be configured per npm package. The first publish must therefore happen package-by-package.

Preferred path:

1. Add repository secret `NPM_TOKEN`.
2. Run [`.github/workflows/bootstrap-publish.yml`](../.github/workflows/bootstrap-publish.yml) with the target version.
3. After bootstrap publish succeeds, connect each package to GitHub Actions trusted publishing on npm.
4. From the next release onward, use [`.github/workflows/release.yml`](../.github/workflows/release.yml) only.

Publish order:

1. `@baerae/zkap-zkp-node-darwin-x64`
2. `@baerae/zkap-zkp-node-darwin-arm64`
3. `@baerae/zkap-zkp-node-linux-x64-gnu`
4. `@baerae/zkap-zkp-node-linux-x64-musl`
5. `@baerae/zkap-zkp-node`
6. `@baerae/zkap-zkp-wasm`
7. `@baerae/zkap-zkp-react-native`
8. `@baerae/zkap-zkp`

For each package in that order:

1. Publish it once manually with a temporary npm token or other approved bootstrap method.
2. Open the package settings on npm and connect the GitHub repository as a trusted publisher for GitHub Actions.
3. Confirm the package now shows the trusted publisher relationship before moving to the next package.

After all 8 packages are connected:

1. Remove `NPM_TOKEN`-based publishing from operational use.
2. Use the GitHub Actions release workflow as the only supported publish path.

## Operational notes

- The root `package-lock.json` is committed state. Do not regenerate it during release unless dependencies changed.
- `@baerae/zkap-zkp-wasm` publishes from `packages/sdk-wasm`, with `pkg/` treated as generated content inside the published package.
- `@baerae/zkap-zkp-react-native` publishes from `packages/sdk-react-native`, with the iOS XCFramework and Android `.so` files downloaded into the package by CI before publish.
- `@baerae/zkap-zkp` is the public Node package. `@baerae/zkap-zkp-node` and the platform packages are internal distribution building blocks, not primary install targets.

## Immediate post-publish verification

Run [`.github/workflows/published-install-smoke.yml`](../.github/workflows/published-install-smoke.yml)
with the published version. It verifies fresh npm installs on:

- `macos-latest`
- `node:20-alpine` (`linux x64 musl`)

Manual checks for the first environments you plan to use:

### Local MacBook

```bash
TMP_DIR="$(mktemp -d)"
cd "$TMP_DIR"
npm init -y
npm install @baerae/zkap-zkp@<version>
node -e "const { generateHash } = require('@baerae/zkap-zkp'); const out = generateHash(['1']); if (!/^0x[0-9a-f]{64}$/i.test(out)) throw new Error(out); console.log(out)"
```

### Google Cloud VM (`x64-musl`)

```bash
TMP_DIR="$(mktemp -d)"
cd "$TMP_DIR"
npm init -y
npm install @baerae/zkap-zkp@<version>
node -e "const { generateHash } = require('@baerae/zkap-zkp'); const out = generateHash(['1']); if (!/^0x[0-9a-f]{64}$/i.test(out)) throw new Error(out); console.log(out)"
```

If the VM does not already have a musl-based Node runtime, run the same check inside a `node:20-alpine` container instead.
