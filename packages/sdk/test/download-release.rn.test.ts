import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  downloadRelease,
  getCachedReleaseInfo,
} from '../src/react-native';
import type { DownloadReleaseProgress } from '../src/types';
import { BASE_URL, makeFetch, makeNetwork, makeRelease, SHAPE } from './fixtures';
import { __configureExpoFs, __files, __resetExpoFs } from './stubs/expo-fs';

const CACHE_DIR = '/cache';

beforeEach(() => {
  __resetExpoFs();
});

afterEach(() => {
  __resetExpoFs();
});

describe('react-native downloadRelease', () => {
  it('emits real-time progress and normalizes to whole-release percent', async () => {
    const release = makeRelease();
    __configureExpoFs({ network: makeNetwork(release), chunks: 3 });

    const events: DownloadReleaseProgress[] = [];
    const result = await downloadRelease({
      baseUrl: BASE_URL,
      shape: SHAPE,
      cacheDir: CACHE_DIR,
      fetch: makeFetch(release),
      onProgress: (p) => events.push(p),
    });

    expect(result.releaseSha).toBe(release.releaseSha);

    // Real-time progress: each large artifact emits several callbacks, not just one.
    const pkEvents = events.filter((e) => e.artifact === 'pk.bin');
    expect(pkEvents.length).toBeGreaterThanOrEqual(3);

    const artifactEvents = events.filter((e) => e.phase === 'artifact');
    for (const e of artifactEvents) {
      expect(e.releaseTotalBytes).toBe(release.releaseTotalBytes);
      expect(e.releaseLoadedBytes!).toBeLessThanOrEqual(e.releaseTotalBytes!);
      expect(e.percent!).toBeGreaterThanOrEqual(0);
      expect(e.percent!).toBeLessThanOrEqual(1);
    }

    // A small artifact completing must not read as the whole release being done.
    const firstArtifact = events.filter((e) => e.artifact === 'circuit.ar1cs');
    const maxFirstPercent = Math.max(...firstArtifact.map((e) => e.percent ?? 0));
    expect(maxFirstPercent).toBeLessThan(0.5);

    // releaseLoadedBytes is monotonic non-decreasing.
    const loaded = artifactEvents
      .map((e) => e.releaseLoadedBytes)
      .filter((v): v is number => typeof v === 'number');
    for (let i = 1; i < loaded.length; i += 1) {
      expect(loaded[i]).toBeGreaterThanOrEqual(loaded[i - 1]);
    }

    const done = events.at(-1)!;
    expect(done.phase).toBe('done');
    expect(done.percent).toBe(1);

    const info = await getCachedReleaseInfo({
      cacheDir: CACHE_DIR,
      shape: SHAPE,
      expectedReleaseSha: release.releaseSha,
    });
    expect(info).toMatchObject({ exists: true, valid: true, totalBytes: release.releaseTotalBytes });
  });

  it('cleans up staging and rejects when an artifact size is wrong', async () => {
    const release = makeRelease();
    const network = makeNetwork(release);
    // Serve a truncated pk.bin so the staged size no longer matches the manifest.
    network.set(`${SHAPE}-pk.bin`, { bytes: release.contents.get('pk.bin')!.slice(0, 100) });
    __configureExpoFs({ network });

    await expect(
      downloadRelease({
        baseUrl: BASE_URL,
        shape: SHAPE,
        cacheDir: CACHE_DIR,
        fetch: makeFetch(release),
      }),
    ).rejects.toThrow(/invalid size/);

    // No staged or temp files should survive.
    const leftover = [...__files().keys()].filter((k) => k.includes('zkap-release-'));
    expect(leftover).toEqual([]);
  });

  it('rejects with an AbortError and cleans up when aborted mid-download', async () => {
    const release = makeRelease();
    __configureExpoFs({ network: makeNetwork(release), chunks: 3 });
    const controller = new AbortController();

    await expect(
      downloadRelease({
        baseUrl: BASE_URL,
        shape: SHAPE,
        cacheDir: CACHE_DIR,
        fetch: makeFetch(release),
        signal: controller.signal,
        onProgress: (p) => {
          if (p.phase === 'artifact' && p.artifact === 'pk.bin') controller.abort();
        },
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });

    const info = await getCachedReleaseInfo({
      cacheDir: CACHE_DIR,
      shape: SHAPE,
      expectedReleaseSha: release.releaseSha,
    });
    expect(info.exists).toBe(false);
  });

  it('returns the cached release without downloading artifacts again', async () => {
    const release = makeRelease();
    __configureExpoFs({ network: makeNetwork(release), chunks: 2 });

    await downloadRelease({ baseUrl: BASE_URL, shape: SHAPE, cacheDir: CACHE_DIR, fetch: makeFetch(release) });

    const events: DownloadReleaseProgress[] = [];
    await downloadRelease({
      baseUrl: BASE_URL,
      shape: SHAPE,
      cacheDir: CACHE_DIR,
      fetch: makeFetch(release),
      onProgress: (p) => events.push(p),
    });
    expect(events.some((e) => e.phase === 'artifact')).toBe(false);
  });
});
