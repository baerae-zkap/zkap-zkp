import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { downloadRelease, getCachedReleaseInfo } from '../src/node';
import type { DownloadReleaseProgress } from '../src/types';
import { BASE_URL, makeFetch, makeRelease, SHAPE } from './fixtures';

let cacheDir: string;

beforeEach(async () => {
  cacheDir = await mkdtemp(join(tmpdir(), 'zkap-dl-node-'));
});

afterEach(async () => {
  await rm(cacheDir, { recursive: true, force: true });
});

describe('node downloadRelease', () => {
  it('downloads, stages, and reports monotonic whole-release progress', async () => {
    const release = makeRelease();
    const events: DownloadReleaseProgress[] = [];

    const result = await downloadRelease({
      baseUrl: BASE_URL,
      shape: SHAPE,
      cacheDir,
      fetch: makeFetch(release),
      onProgress: (p) => events.push(p),
    });

    expect(result.releaseSha).toBe(release.releaseSha);
    const info = await getCachedReleaseInfo({
      cacheDir,
      shape: SHAPE,
      expectedReleaseSha: release.releaseSha,
    });
    expect(info).toMatchObject({ exists: true, valid: true });

    // manifest.json downloads before its own contents are parsed, so the whole-release
    // total is only known from the next artifact onward.
    const artifactEvents = events.filter(
      (e) => e.phase === 'artifact' && e.artifact !== 'manifest.json',
    );
    for (const e of artifactEvents) {
      expect(e.releaseTotalBytes).toBe(release.releaseTotalBytes);
    }

    // releaseLoadedBytes is monotonic non-decreasing and never exceeds the total.
    const loaded = artifactEvents
      .map((e) => e.releaseLoadedBytes)
      .filter((v): v is number => typeof v === 'number');
    for (let i = 1; i < loaded.length; i += 1) {
      expect(loaded[i]).toBeGreaterThanOrEqual(loaded[i - 1]);
    }
    for (const e of artifactEvents) {
      expect(e.releaseLoadedBytes!).toBeLessThanOrEqual(e.releaseTotalBytes!);
      expect(e.percent!).toBeGreaterThanOrEqual(0);
      expect(e.percent!).toBeLessThanOrEqual(1);
      // Deprecated fields mirror artifact-scoped values.
      expect(e.loadedBytes).toBe(e.artifactLoadedBytes);
      expect(e.totalBytes).toBe(e.artifactTotalBytes);
    }

    const done = events.at(-1)!;
    expect(done.phase).toBe('done');
    expect(done.percent).toBe(1);
    expect(done.releaseLoadedBytes).toBe(release.releaseTotalBytes);
  });

  it('cleans up the staging dir and rejects on a SHA256 mismatch', async () => {
    const release = makeRelease();
    await expect(
      downloadRelease({
        baseUrl: BASE_URL,
        shape: SHAPE,
        cacheDir,
        fetch: makeFetch(release, { corrupt: 'pk.bin' }),
      }),
    ).rejects.toThrow(/SHA256 mismatch/);

    const info = await getCachedReleaseInfo({
      cacheDir,
      shape: SHAPE,
      expectedReleaseSha: release.releaseSha,
    });
    expect(info.exists).toBe(false);
    // The temp staging directory must not survive a failed download.
    const stagedTmp = join(cacheDir, `zkap-release-${release.releaseSha}-${SHAPE}.tmp`);
    await expect(rm(stagedTmp, { recursive: true })).rejects.toThrow();
  });

  it('rejects with an AbortError and cleans up when aborted mid-download', async () => {
    const release = makeRelease();
    const controller = new AbortController();

    await expect(
      downloadRelease({
        baseUrl: BASE_URL,
        shape: SHAPE,
        cacheDir,
        fetch: makeFetch(release),
        signal: controller.signal,
        onProgress: (p) => {
          if (p.phase === 'artifact' && p.artifact === 'pk.bin') controller.abort();
        },
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });

    const info = await getCachedReleaseInfo({
      cacheDir,
      shape: SHAPE,
      expectedReleaseSha: release.releaseSha,
    });
    expect(info.exists).toBe(false);
  });

  it('returns the cached release without re-fetching on the second call', async () => {
    const release = makeRelease();
    const fetchSpy = vi.fn(makeFetch(release));

    await downloadRelease({ baseUrl: BASE_URL, shape: SHAPE, cacheDir, fetch: fetchSpy });
    const firstCalls = fetchSpy.mock.calls.length;
    expect(firstCalls).toBeGreaterThan(0);

    const events: DownloadReleaseProgress[] = [];
    await downloadRelease({
      baseUrl: BASE_URL,
      shape: SHAPE,
      cacheDir,
      fetch: fetchSpy,
      onProgress: (p) => events.push(p),
    });

    // The warm-cache path only fetches the small SHA256SUMS file, not any artifact.
    expect(events.some((e) => e.phase === 'artifact')).toBe(false);
    expect(fetchSpy.mock.calls.length).toBe(firstCalls + 1);
  });

  it('reports an absent cache for an unknown release SHA', async () => {
    const info = await getCachedReleaseInfo({
      cacheDir,
      shape: SHAPE,
      expectedReleaseSha: 'deadbeefdeadbeef',
    });
    expect(info).toMatchObject({ exists: false, valid: false });
  });
});
