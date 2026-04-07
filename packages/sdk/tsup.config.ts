import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { node: 'src/node.ts' },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    outDir: 'dist',
  },
  {
    entry: { 'artifact-manager': 'src/artifact-manager.ts' },
    format: ['cjs', 'esm'],
    dts: true,
    outDir: 'dist',
  },
]);
