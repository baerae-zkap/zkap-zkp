// Configurable in-memory stub for `expo-file-system/legacy`, aliased in by
// vitest.config.ts. Tests drive it via `__configureExpoFs` / `__resetExpoFs`.

export interface NetworkEntry {
  bytes: Uint8Array;
}

interface ExpoFsConfig {
  /** Binary artifact bodies keyed by the final URL path segment, e.g. `1-of-1-pk.bin`. */
  network: Map<string, NetworkEntry>;
  /** Number of progress callbacks emitted per artifact download. */
  chunks: number;
}

interface StubState extends ExpoFsConfig {
  /** Staged filesystem: absolute-ish path -> bytes or text. */
  store: Map<string, Uint8Array | string>;
}

export const cacheDirectory = 'file:///cache/';
export const documentDirectory = 'file:///docs/';

let state: StubState = freshState();

function freshState(): StubState {
  return { network: new Map(), chunks: 2, store: new Map() };
}

export function __resetExpoFs(): void {
  state = freshState();
}

export function __configureExpoFs(config: Partial<ExpoFsConfig>): void {
  if (config.network) state.network = config.network;
  if (typeof config.chunks === 'number') state.chunks = config.chunks;
}

export function __files(): Map<string, Uint8Array | string> {
  return state.store;
}

function pathOf(uri: string): string {
  return uri.replace(/^file:\/\//, '').replace(/\/+$/, '');
}

function lastSegment(url: string): string {
  const withoutQuery = url.split(/[?#]/)[0];
  const parts = withoutQuery.split('/');
  return decodeURIComponent(parts[parts.length - 1] ?? '');
}

function byteLength(value: Uint8Array | string): number {
  return typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : value.length;
}

interface ExpoFileInfo {
  exists: boolean;
  isDirectory?: boolean;
  size?: number;
}

export async function getInfoAsync(fileUri: string): Promise<ExpoFileInfo> {
  const value = state.store.get(pathOf(fileUri));
  if (value === undefined) return { exists: false };
  return { exists: true, isDirectory: false, size: byteLength(value) };
}

export async function makeDirectoryAsync(): Promise<void> {
  // Directories are implicit in the in-memory store.
}

export async function deleteAsync(
  uri: string,
  _options?: { idempotent?: boolean },
): Promise<void> {
  const target = pathOf(uri);
  const prefix = `${target}/`;
  for (const key of [...state.store.keys()]) {
    if (key === target || key.startsWith(prefix)) {
      state.store.delete(key);
    }
  }
}

export async function moveAsync(options: { from: string; to: string }): Promise<void> {
  const from = pathOf(options.from);
  const to = pathOf(options.to);
  const fromPrefix = `${from}/`;
  for (const [key, value] of [...state.store.entries()]) {
    if (key === from || key.startsWith(fromPrefix)) {
      const rest = key.slice(from.length);
      state.store.delete(key);
      state.store.set(`${to}${rest}`, value);
    }
  }
}

export async function readAsStringAsync(fileUri: string): Promise<string> {
  const value = state.store.get(pathOf(fileUri));
  if (value === undefined) {
    throw new Error(`[test-expo-fs] file not found: ${fileUri}`);
  }
  return typeof value === 'string'
    ? value
    : Buffer.from(value).toString('utf8');
}

export async function writeAsStringAsync(
  fileUri: string,
  contents: string,
): Promise<void> {
  state.store.set(pathOf(fileUri), contents);
}

interface DownloadProgressData {
  totalBytesWritten: number;
  totalBytesExpectedToWrite: number;
}

export function createDownloadResumable(
  uri: string,
  fileUri: string,
  _options?: Record<string, unknown>,
  callback?: (data: DownloadProgressData) => void,
) {
  let cancelled = false;
  return {
    async downloadAsync(): Promise<unknown> {
      const segment = lastSegment(uri);
      const entry = state.network.get(segment);
      if (!entry) {
        throw new Error(`[test-expo-fs] no network entry for ${segment}`);
      }
      const total = entry.bytes.length;
      const chunks = Math.max(1, state.chunks);
      for (let i = 1; i <= chunks; i += 1) {
        const written = Math.floor((total * i) / chunks);
        callback?.({ totalBytesWritten: written, totalBytesExpectedToWrite: total });
        if (cancelled) {
          const error = new Error('[test-expo-fs] download cancelled');
          error.name = 'AbortError';
          throw error;
        }
      }
      state.store.set(pathOf(fileUri), entry.bytes.slice());
      return { uri: fileUri };
    },
    async pauseAsync(): Promise<unknown> {
      return undefined;
    },
    async resumeAsync(): Promise<unknown> {
      return undefined;
    },
    async cancelAsync(): Promise<void> {
      cancelled = true;
    },
  };
}
