import { createHash } from 'node:crypto';
import { computeReleaseSha, releaseFileName } from '../src/release-shared';
import type { NetworkEntry } from './stubs/expo-fs';

export const SHAPE = '1-of-1';
export const BASE_URL = 'https://releases.example.com/zkap';

/** Release artifacts that are downloaded as files, excluding `manifest.json`. */
const RELEASE_ARTIFACTS = [
  'circuit.ar1cs',
  'pk.bin',
  'vk.bin',
  'pvk.bin',
  'Groth16Verifier.sol',
  'config.json',
] as const;

const WITNESS_GEN = 'witness_gen.wasm';

function sha256(bytes: Uint8Array | string): string {
  return createHash('sha256')
    .update(typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes)
    .digest('hex');
}

export interface Release {
  /** Artifact name -> file bytes (the 6 release artifacts + witness_gen.wasm). */
  contents: Map<string, Uint8Array>;
  manifestJson: string;
  sha256SumsText: string;
  releaseSha: string;
  /** Total downloaded bytes excluding manifest.json (== sum of manifest artifact sizes). */
  releaseTotalBytes: number;
  /** Largest single artifact size, used to assert non-trivial progress. */
  largestArtifactBytes: number;
}

/** Build a deterministic fake release whose SHA256SUMS and manifest are internally consistent. */
export function makeRelease(): Release {
  const contents = new Map<string, Uint8Array>();
  const sizes: Record<string, number> = {
    'circuit.ar1cs': 64,
    'pk.bin': 4096, // largest, stands in for the ~700MB proving key
    'vk.bin': 32,
    'pvk.bin': 48,
    'Groth16Verifier.sol': 96,
    'config.json': 128,
    [WITNESS_GEN]: 512,
  };
  let fill = 1;
  for (const [name, size] of Object.entries(sizes)) {
    contents.set(name, new Uint8Array(size).fill(fill));
    fill += 1;
  }

  const manifestArtifacts: Record<string, { path: string; sha256: string; size: number }> = {};
  let releaseTotalBytes = 0;
  let largestArtifactBytes = 0;
  for (const [name, bytes] of contents) {
    const key = name.replace(/[^a-zA-Z0-9]/g, '_');
    manifestArtifacts[key] = { path: name, sha256: sha256(bytes), size: bytes.length };
    releaseTotalBytes += bytes.length;
    largestArtifactBytes = Math.max(largestArtifactBytes, bytes.length);
  }
  const manifestJson = JSON.stringify({ artifacts: manifestArtifacts });

  const sumsLines: string[] = [`${sha256(manifestJson)}  manifest.json`];
  for (const name of [...RELEASE_ARTIFACTS, WITNESS_GEN]) {
    sumsLines.push(`${sha256(contents.get(name)!)}  ${name}`);
  }
  const sha256SumsText = `${sumsLines.join('\n')}\n`;

  return {
    contents,
    manifestJson,
    sha256SumsText,
    releaseSha: computeReleaseSha(sha256SumsText),
    releaseTotalBytes,
    largestArtifactBytes,
  };
}

/** Network map for the React Native expo-file-system stub (binary artifacts only). */
export function makeNetwork(release: Release): Map<string, NetworkEntry> {
  const network = new Map<string, NetworkEntry>();
  for (const name of RELEASE_ARTIFACTS) {
    network.set(releaseFileName(SHAPE, name), { bytes: release.contents.get(name)! });
  }
  network.set(WITNESS_GEN, { bytes: release.contents.get(WITNESS_GEN)! });
  return network;
}

export interface FetchOptions {
  /** Corrupt the body served for this artifact name to force a SHA256 mismatch. */
  corrupt?: string;
}

function textResponse(body: string): Response {
  return new Response(body, { headers: { 'content-length': String(Buffer.byteLength(body)) } });
}

function binaryResponse(bytes: Uint8Array): Response {
  return new Response(bytes, { headers: { 'content-length': String(bytes.length) } });
}

/**
 * A `fetch` implementation that serves a {@link Release} for every release URL
 * (SHA256SUMS, manifest.json, and every binary artifact). Used by the Node tests,
 * which download all files over fetch.
 */
export function makeFetch(release: Release, options: FetchOptions = {}): typeof fetch {
  return (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    const segment = decodeURIComponent(url.split(/[?#]/)[0].split('/').pop() ?? '');
    const name = segment.startsWith(`${SHAPE}-`)
      ? segment.slice(`${SHAPE}-`.length)
      : segment;

    if (name === 'SHA256SUMS') return textResponse(release.sha256SumsText);
    if (name === 'manifest.json') return textResponse(release.manifestJson);

    const bytes = release.contents.get(name);
    if (!bytes) {
      return new Response(`not found: ${name}`, { status: 404 });
    }
    if (options.corrupt === name) {
      const corrupted = bytes.slice();
      corrupted[0] = (corrupted[0] ?? 0) ^ 0xff;
      return binaryResponse(corrupted);
    }
    return binaryResponse(bytes);
  }) as typeof fetch;
}
