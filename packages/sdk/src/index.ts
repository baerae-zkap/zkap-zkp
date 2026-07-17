import { initZkap as initNodeZkap } from './node';
import type { InitInput, InitOutput } from './types';

export * from './errors';
export * from './types';

export {
  deriveSelector,
  generateAnchor,
  generateAudHash,
  generateHash,
  generateLeafHash,
  downloadRelease,
  downloadWitnessGen,
  getCachedReleaseInfo,
  getCachedWitnessGenInfo,
  loadCircuitConfig,
  loadRelease,
  normalizeCircuitConfig,
  prepareProver,
  prove,
  resolveWitnessGenPaths,
  verify,
} from './node';

export async function initZkap(
  _moduleOrPath?: InitInput,
): Promise<void | InitOutput> {
  return initNodeZkap();
}
