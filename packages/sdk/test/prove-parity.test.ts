import { beforeEach, describe, expect, it, vi } from 'vitest';

// ── Backend prover spies ─────────────────────────────────────────────────────
// `node` and `node-sync` share ONE native backend (`@baerae/zkap-zkp-node`);
// `react-native` has its own. Each spy models the prover as a PURE function of
// the request it receives AFTER the facade has formatted it. Because the modeled
// output depends on the merkle-path ORDER, the parity assertions below fail if a
// facade forgets to format (the original `issuer-key leaf is not a member of
// merkle_root` bug) OR formats twice (a double reverse).
const { nodeProveSpy, rnProveSpy } = vi.hoisted(() => ({
  nodeProveSpy: vi.fn(),
  rnProveSpy: vi.fn(),
}));

vi.mock('@baerae/zkap-zkp-node', () => ({
  prove: nodeProveSpy,
  generateAnchor: vi.fn(),
  generateAudHash: vi.fn(),
  generateHash: vi.fn(),
  generateLeafHash: vi.fn(),
  loadRelease: vi.fn(),
  prepareProver: vi.fn(),
  verify: vi.fn(),
}));

vi.mock('@baerae/zkap-zkp-react-native', () => ({
  prove: rnProveSpy,
  generateAnchor: vi.fn(),
  generateAudHash: vi.fn(),
  generateHash: vi.fn(),
  generateLeafHash: vi.fn(),
}));

// `wasm.prove()` throws before it ever touches the backend; this mock only needs
// to make `import … from '@baerae/zkap-zkp-wasm'` resolve in a plain Node test
// process (the real package's wasm entry is not loadable here).
vi.mock('@baerae/zkap-zkp-wasm', () => ({
  default: vi.fn(),
  generateAnchor: vi.fn(),
  generateAudHash: vi.fn(),
  generateHash: vi.fn(),
  generateLeafHash: vi.fn(),
}));

import * as nodeFacade from '../src/node';
import * as nodeSyncFacade from '../src/node-sync';
import * as rnFacade from '../src/react-native';
import * as wasmFacade from '../src/wasm';
import { UnsupportedPlatformError } from '../src/errors';
import { formatMerklePathForCircuit } from '../src/merkle';
import type { CircuitConfig, ProofOutput, ProofRequest } from '../src/types';

// ── Deterministic prover model ───────────────────────────────────────────────
// The proof is a pure function of the crypto-relevant inputs — crucially the
// merkle path each credential carries. `witnessGenPath`/`manifestDir` only LOCATE
// the prover and must NOT affect the proof, so they are deliberately excluded
// here: that lets `node` (which rewrites witnessGenPath) and `node-sync` (which
// does not) still agree.
function nativeOutput(req: ProofRequest): ProofOutput {
  return {
    proofs: req.credentials.map((c) => [...c.merklePath]),
    sharedInputs: [req.merkleRoot, req.random, req.hSignUserOp, ...req.anchor],
    partialRhsList: req.credentials.map((c) => c.merklePath.join(',')),
    jwtExpList: req.credentials.map((c) => String(c.merkleLeafIdx)),
  } as ProofOutput;
}

// React Native's bridge returns snake_case keys, which the facade remaps. Mirror
// that so the RN path exercises the real mapping in `react-native.ts`.
function rnOutput(req: ProofRequest) {
  const o = nativeOutput(req);
  return {
    proofs: o.proofs,
    shared_inputs: o.sharedInputs,
    partial_rhs_list: o.partialRhsList,
    jwt_exp_list: o.jwtExpList,
  };
}

const config = {} as unknown as CircuitConfig;

// Raw request EXACTLY as the on-chain `getMerklePath()` yields it: bottom→root,
// `merklePath[0]` = leaf sibling. The inner segment has length ≥ 2 so the
// circuit reorder is observable (a no-op format would make the test vacuous).
function rawRequest(): ProofRequest {
  return {
    manifestDir: '/crs',
    witnessGenPath: '/wg/witness_gen.wasm',
    witnessGenSidecarPath: '/wg/witness_gen.json',
    random: '0x01',
    hSignUserOp: '0x02',
    anchor: ['0xa0', '0xa1'],
    merkleRoot: '0xroot',
    credentials: [
      { jwt: 'jwtA', rsaModulusB64: 'modA', merklePath: ['SIB_A', 'A1', 'A2', 'A3'], merkleLeafIdx: 0 },
      { jwt: 'jwtB', rsaModulusB64: 'modB', merklePath: ['SIB_B', 'B1', 'B2', 'B3'], merkleLeafIdx: 1 },
    ],
  };
}

// The proof-bearing fields, normalized across facades. `node`/`node-sync` echo
// the native `timing` (nondeterministic wall-clock) while RN drops it, so the
// cross-facade comparison is on the cryptographic core only.
const cryptoCore = (o: ProofOutput) => ({
  proofs: o.proofs,
  sharedInputs: o.sharedInputs,
  partialRhsList: o.partialRhsList,
  jwtExpList: o.jwtExpList,
});

const pathsPassedTo = (spy: typeof nodeProveSpy, call: number): string[][] =>
  (spy.mock.calls[call][1] as ProofRequest).credentials.map((c) => c.merklePath);

beforeEach(() => {
  nodeProveSpy.mockReset().mockImplementation((_c: unknown, req: ProofRequest) => nativeOutput(req));
  rnProveSpy.mockReset().mockImplementation((_c: unknown, req: ProofRequest) => rnOutput(req));
});

describe('prove() facade parity', () => {
  it('node, node-sync and react-native return identical proof output for identical input', async () => {
    const outNode = await nodeFacade.prove(config, rawRequest());
    const outSync = nodeSyncFacade.prove(config, rawRequest()); // synchronous — no await
    const outRn = await rnFacade.prove(config, rawRequest());

    expect(cryptoCore(outSync)).toEqual(cryptoCore(outNode));
    expect(cryptoCore(outRn)).toEqual(cryptoCore(outNode));
  });

  it('every proving facade reorders the merkle path EXACTLY ONCE via formatMerklePathForCircuit', async () => {
    await nodeFacade.prove(config, rawRequest()); // nodeProveSpy call 0 (node)
    nodeSyncFacade.prove(config, rawRequest()); //   nodeProveSpy call 1 (node-sync)
    await rnFacade.prove(config, rawRequest()); //    rnProveSpy   call 0 (react-native)

    const raw = rawRequest();
    const expected = raw.credentials.map((c) => formatMerklePathForCircuit(c.merklePath));
    const rawPaths = raw.credentials.map((c) => c.merklePath);

    // Sanity: the reorder must actually change the order, else every assertion
    // below would pass even for a facade that does nothing.
    expect(expected).not.toEqual(rawPaths);

    expect(pathsPassedTo(nodeProveSpy, 0)).toEqual(expected); // node
    expect(pathsPassedTo(nodeProveSpy, 1)).toEqual(expected); // node-sync
    expect(pathsPassedTo(rnProveSpy, 0)).toEqual(expected); // react-native
  });

  it('node-sync no longer forwards the raw contract path (regression guard for the merkle_root error)', () => {
    nodeSyncFacade.prove(config, rawRequest());
    expect(pathsPassedTo(nodeProveSpy, 0)).not.toEqual(
      rawRequest().credentials.map((c) => c.merklePath),
    );
  });

  it('wasm has no prover and refuses consistently (proving is delegated to node / react-native)', async () => {
    await expect(wasmFacade.prove(config, rawRequest())).rejects.toBeInstanceOf(
      UnsupportedPlatformError,
    );
  });

  it('node-sync exposes the same merkle helpers as the node facade', () => {
    expect(typeof nodeSyncFacade.formatMerklePathForCircuit).toBe('function');
    expect(typeof nodeSyncFacade.withFormattedMerklePaths).toBe('function');
    expect(nodeSyncFacade.formatMerklePathForCircuit(['x', 'a', 'b', 'c'])).toEqual(
      nodeFacade.formatMerklePathForCircuit(['x', 'a', 'b', 'c']),
    );
  });
});
