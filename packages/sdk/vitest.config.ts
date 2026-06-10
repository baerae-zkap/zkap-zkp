import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const stub = (relativePath: string): string =>
  fileURLToPath(new URL(relativePath, import.meta.url));

// The facade source statically imports the native runtime packages and dynamically
// imports `expo-file-system/legacy`. None of those can load in a plain Node test
// process (native binaries / React Native / not installed), so they are aliased to
// lightweight in-memory stubs. download/staging logic itself is pure TypeScript.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
  resolve: {
    alias: {
      '@baerae/zkap-zkp-node': stub('./test/stubs/zkap-node.ts'),
      '@baerae/zkap-zkp-react-native': stub('./test/stubs/zkap-rn.ts'),
      'expo-file-system/legacy': stub('./test/stubs/expo-fs.ts'),
    },
  },
});
