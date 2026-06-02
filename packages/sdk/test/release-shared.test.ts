import { describe, expect, it } from 'vitest';
import {
  buildArtifactProgress,
  makeAbortError,
  sumManifestBytes,
  throwIfAborted,
} from '../src/release-shared';

const MANIFEST = JSON.stringify({
  artifacts: {
    pk: { path: 'pk.bin', sha256: 'a'.repeat(64), size: 100 },
    vk: { path: 'vk.bin', sha256: 'b'.repeat(64), size: 20 },
    wg: { path: 'witness_gen.wasm', sha256: 'c'.repeat(64), size: 30 },
  },
});

describe('sumManifestBytes', () => {
  it('sums every artifact size', () => {
    expect(sumManifestBytes(MANIFEST)).toBe(150);
  });

  it('honours excludePaths', () => {
    expect(sumManifestBytes(MANIFEST, { excludePaths: ['witness_gen.wasm'] })).toBe(120);
  });

  it('returns undefined when any size is missing', () => {
    const partial = JSON.stringify({
      artifacts: {
        pk: { path: 'pk.bin', sha256: 'a'.repeat(64), size: 100 },
        vk: { path: 'vk.bin', sha256: 'b'.repeat(64) },
      },
    });
    expect(sumManifestBytes(partial)).toBeUndefined();
  });
});

describe('buildArtifactProgress', () => {
  const base = {
    phase: 'artifact' as const,
    artifact: 'pk.bin',
    completedArtifacts: 1,
    totalArtifacts: 8,
  };

  it('populates both deprecated and explicit byte fields', () => {
    const p = buildArtifactProgress(base, 50, 100, 250, 1000);
    expect(p.loadedBytes).toBe(50);
    expect(p.totalBytes).toBe(100);
    expect(p.artifactLoadedBytes).toBe(50);
    expect(p.artifactTotalBytes).toBe(100);
    expect(p.releaseLoadedBytes).toBe(250);
    expect(p.releaseTotalBytes).toBe(1000);
    expect(p.percent).toBeCloseTo(0.25);
  });

  it('omits percent when the release total is unknown', () => {
    const p = buildArtifactProgress(base, 50, undefined, undefined, undefined);
    expect(p.percent).toBeUndefined();
    expect(p.releaseTotalBytes).toBeUndefined();
  });

  it('clamps percent to 1', () => {
    const p = buildArtifactProgress(base, 100, 100, 1200, 1000);
    expect(p.percent).toBe(1);
  });
});

describe('abort helpers', () => {
  it('makeAbortError produces an AbortError', () => {
    const error = makeAbortError();
    expect(error.name).toBe('AbortError');
  });

  it('throwIfAborted throws only when aborted', () => {
    const controller = new AbortController();
    expect(() => throwIfAborted(controller.signal)).not.toThrow();
    expect(() => throwIfAborted(undefined)).not.toThrow();
    controller.abort();
    expect(() => throwIfAborted(controller.signal)).toThrowError(/aborted/);
  });
});
