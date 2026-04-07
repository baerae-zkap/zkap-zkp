import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { node: 'src/node.ts' },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.mjs' }),
  },
  {
    entry: { 'artifact-manager': 'src/artifact-manager.ts' },
    format: ['cjs', 'esm'],
    dts: true,
    outDir: 'dist',
    outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.mjs' }),
  },
]);
