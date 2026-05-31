import type { CircuitConfig } from './types';

export const RELEASE_ARTIFACT_NAMES = [
  'manifest.json',
  'circuit.ar1cs',
  'pk.bin',
  'vk.bin',
  'pvk.bin',
  'Groth16Verifier.sol',
  'config.json',
] as const;

export const WITNESS_GEN_NAME = 'witness_gen.wasm';

export type ReleaseArtifactName =
  | (typeof RELEASE_ARTIFACT_NAMES)[number]
  | typeof WITNESS_GEN_NAME;

export interface ManifestArtifact {
  path: string;
  sha256: string;
  size?: number;
}

export interface ReleaseManifest {
  artifacts: Record<string, ManifestArtifact | undefined>;
}

const HEX = '0123456789abcdef';
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
  0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
  0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
  0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
  0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
] as const;

function utf8Bytes(value: string): Uint8Array {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(value);
  }

  const bytes: number[] = [];
  for (let i = 0; i < value.length; i += 1) {
    let codePoint = value.charCodeAt(i);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < value.length) {
      const low = value.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00);
        i += 1;
      }
    }

    if (codePoint < 0x80) {
      bytes.push(codePoint);
    } else if (codePoint < 0x800) {
      bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint < 0x10000) {
      bytes.push(
        0xe0 | (codePoint >> 12),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    } else {
      bytes.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    }
  }
  return Uint8Array.from(bytes);
}

function rotr(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits));
}

export function sha256HexUtf8(value: string): string {
  const data = utf8Bytes(value);
  const bitLength = data.length * 8;
  const paddedLength = (((data.length + 9 + 63) >> 6) << 6);
  const bytes = new Uint8Array(paddedLength);
  bytes.set(data);
  bytes[data.length] = 0x80;

  const view = new DataView(bytes.buffer);
  const high = Math.floor(bitLength / 0x100000000);
  const low = bitLength >>> 0;
  view.setUint32(paddedLength - 8, high);
  view.setUint32(paddedLength - 4, low);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;
  const w = new Array<number>(64);

  for (let offset = 0; offset < bytes.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((word) => {
      let out = '';
      for (let shift = 28; shift >= 0; shift -= 4) {
        out += HEX[(word >>> shift) & 0xf];
      }
      return out;
    })
    .join('');
}

export function computeReleaseSha(sha256SumsText: string): string {
  return sha256HexUtf8(sha256SumsText).slice(0, 16);
}

export function parseSha256Sums(text: string): Map<string, string> {
  const result = new Map<string, string>();
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;

    const match = /^([0-9a-fA-F]{64})\s+\*?(.+)$/.exec(line);
    if (!match) {
      throw new Error(`Malformed SHA256SUMS line ${index + 1}: ${raw}`);
    }
    result.set(match[2], match[1].toLowerCase());
  });
  return result;
}

export function releaseFileName(shape: string, artifactName: string): string {
  return artifactName === WITNESS_GEN_NAME ? WITNESS_GEN_NAME : `${shape}-${artifactName}`;
}

export function validateReleaseShape(shape: string): void {
  if (!/^[A-Za-z0-9._-]+$/.test(shape)) {
    throw new Error(
      `[zkap-zkp] invalid release shape ${JSON.stringify(shape)}; expected letters, numbers, dots, underscores, or hyphens`,
    );
  }
}

export function releaseFileUrl(baseUrl: string, fileName: string): string {
  const cleanBase = baseUrl.replace(/\/+$/, '');
  return `${cleanBase}/${fileName
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/')}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function readNumber(
  source: Record<string, unknown>,
  camelKey: keyof CircuitConfig,
  snakeKey: string,
): number {
  const value = source[camelKey] ?? source[snakeKey];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`[zkap-zkp] invalid circuit config field ${String(camelKey)}`);
  }
  return value;
}

function readString(
  source: Record<string, unknown>,
  camelKey: keyof CircuitConfig,
  snakeKey: string,
): string {
  const value = source[camelKey] ?? source[snakeKey];
  if (typeof value !== 'string') {
    throw new Error(`[zkap-zkp] invalid circuit config field ${String(camelKey)}`);
  }
  return value;
}

export function normalizeCircuitConfig(input: unknown): CircuitConfig {
  if (!isRecord(input)) {
    throw new Error('[zkap-zkp] circuit config must be an object');
  }

  const claims = input.claims;
  if (!Array.isArray(claims) || claims.some((claim) => typeof claim !== 'string')) {
    throw new Error('[zkap-zkp] invalid circuit config field claims');
  }

  return {
    maxJwtB64Len: readNumber(input, 'maxJwtB64Len', 'max_jwt_b64_len'),
    maxPayloadB64Len: readNumber(input, 'maxPayloadB64Len', 'max_payload_b64_len'),
    maxAudLen: readNumber(input, 'maxAudLen', 'max_aud_len'),
    maxExpLen: readNumber(input, 'maxExpLen', 'max_exp_len'),
    maxIssLen: readNumber(input, 'maxIssLen', 'max_iss_len'),
    maxNonceLen: readNumber(input, 'maxNonceLen', 'max_nonce_len'),
    maxSubLen: readNumber(input, 'maxSubLen', 'max_sub_len'),
    n: readNumber(input, 'n', 'n'),
    k: readNumber(input, 'k', 'k'),
    treeHeight: readNumber(input, 'treeHeight', 'tree_height'),
    numAudienceLimit: readNumber(input, 'numAudienceLimit', 'num_audience_limit'),
    claims: [...claims],
    forbiddenString: readString(input, 'forbiddenString', 'forbidden_string'),
  };
}

export function parseReleaseManifest(manifestJson: string): ReleaseManifest {
  const parsed = JSON.parse(manifestJson) as unknown;
  if (!isRecord(parsed) || !isRecord(parsed.artifacts)) {
    throw new Error('[zkap-zkp] malformed release manifest: artifacts missing');
  }
  return parsed as unknown as ReleaseManifest;
}

export function listManifestArtifacts(manifestJson: string): ManifestArtifact[] {
  const manifest = parseReleaseManifest(manifestJson);
  const artifacts: ManifestArtifact[] = [];
  const seen = new Set<string>();

  for (const artifact of Object.values(manifest.artifacts)) {
    if (!artifact || !artifact.path || !artifact.sha256) continue;
    if (seen.has(artifact.path)) continue;
    seen.add(artifact.path);
    artifacts.push({
      path: artifact.path,
      sha256: artifact.sha256.toLowerCase(),
      size: artifact.size,
    });
  }

  return artifacts;
}

export function findManifestArtifact(
  manifestJson: string,
  path: string,
): ManifestArtifact {
  const artifact = listManifestArtifacts(manifestJson).find(
    (entry) => entry.path === path,
  );
  if (!artifact) {
    if (path === WITNESS_GEN_NAME) {
      throw new Error(
        `[zkap-zkp] incompatible zkap-circuit release: release manifest missing artifact ${WITNESS_GEN_NAME}. Use a zkap-circuit release that includes ${WITNESS_GEN_NAME}.`,
      );
    }
    throw new Error(`[zkap-zkp] release manifest missing artifact ${path}`);
  }
  return artifact;
}
