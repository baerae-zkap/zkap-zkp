import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      node: 'src/node.ts',
      'node-sync': 'src/node-sync.ts',
      wasm: 'src/wasm.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,
    clean: false,
    outDir: 'dist',
    outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.mjs' }),
  },
  {
    entry: { 'react-native': 'src/react-native.ts' },
    format: ['cjs'],
    dts: true,
    clean: false,
    outDir: 'dist',
    outExtension: () => ({ js: '.js' }),
  },
]);
