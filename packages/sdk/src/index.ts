import { initZkap as initNodeZkap } from './node';
import type { InitInput, InitOutput } from './types';

export * from './errors';
export * from './types';

export {
  generateAnchor,
  generateAudHash,
  generateHash,
  generateLeafHash,
  downloadRelease,
  loadCircuitConfig,
  loadRelease,
  normalizeCircuitConfig,
  prepareProver,
  prove,
  verify,
} from './node';

export async function initZkap(
  _moduleOrPath?: InitInput,
): Promise<void | InitOutput> {
  return initNodeZkap();
}
