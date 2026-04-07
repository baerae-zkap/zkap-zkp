/**
 * Proof example: groth16Setup → prove → verify
 * Using @baerae/zkap-zkp-node (native binding)
 *
 * Run: node examples/node/proof-basic.js
 *
 * WARNING: groth16Setup performs a full Groth16 trusted setup.
 * This can take several minutes depending on your machine.
 *
 * Mock input: packages/sdk-node/__test__/mock_proof_input.json
 */

'use strict';

const { groth16Setup, prove, verify } = require('@baerae/zkap-zkp-node');
const { readFileSync, writeFileSync, mkdtempSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');

// Skip manifest.json integrity check — pk is generated in-memory (test only)
process.env['ZKAP_SKIP_MANIFEST_CHECK'] = '1';

const MOCK_INPUT = resolve(__dirname, '../../packages/sdk-node/__test__/mock_proof_input.json');
const mock = JSON.parse(readFileSync(MOCK_INPUT, 'utf8'));

const CONFIG = {
  maxJwtB64Len:     mock.max_jwt_b64_len,
  maxPayloadB64Len: mock.max_payload_b64_len,
  maxAudLen:        mock.max_aud_len,
  maxExpLen:        mock.max_exp_len,
  maxIssLen:        mock.max_iss_len,
  maxNonceLen:      mock.max_nonce_len,
  maxSubLen:        mock.max_sub_len,
  n:                mock.n,
  k:                mock.k,
  treeHeight:       mock.tree_height,
  numAudienceLimit: mock.num_audience_limit,
  claims:           mock.claims,
  forbiddenString:  mock.forbidden_string,
};

async function main() {
  // ── 1. groth16Setup ──────────────────────────────────────────────────────
  console.log('[1/3] groth16Setup... (may take several minutes)');
  const t0 = Date.now();
  const setup = await groth16Setup(CONFIG);
  console.log(`  done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  console.log(`  pk: ${setup.pkBytes.length} bytes, vk: ${setup.vkBytes.length} bytes\n`);

  // ── 2. prove ─────────────────────────────────────────────────────────────
  console.log('[2/3] prove...');

  // Write pk + manifest to a temp dir (prove validates manifest beside pk)
  const tmpDir = mkdtempSync(join(tmpdir(), 'zkap-example-'));
  const pkPath = join(tmpDir, 'pk.bin');
  writeFileSync(pkPath, Buffer.from(setup.pkBytes));
  writeFileSync(join(tmpDir, 'manifest.json'), JSON.stringify({
    profile: 'example',
    params: {
      MAX_JWT_B64_LEN:      CONFIG.maxJwtB64Len,
      MAX_PAYLOAD_B64_LEN:  CONFIG.maxPayloadB64Len,
      MAX_AUD_LEN:          CONFIG.maxAudLen,
      MAX_EXP_LEN:          CONFIG.maxExpLen,
      MAX_ISS_LEN:          CONFIG.maxIssLen,
      MAX_NONCE_LEN:        CONFIG.maxNonceLen,
      MAX_SUB_LEN:          CONFIG.maxSubLen,
      N:                    CONFIG.n,
      K:                    CONFIG.k,
      TREE_HEIGHT:          CONFIG.treeHeight,
      NUM_AUDIENCE_LIMIT:   CONFIG.numAudienceLimit,
    },
  }));

  const request = {
    pkPath,
    jwts:          mock.jwts,
    pkOps:         mock.pk_ops,
    merklePaths:   mock.merkle_paths,
    leafIndices:   mock.leaf_indices,
    root:          mock.root,
    anchor:        mock.anchor,
    hSignUserOp:   mock.h_sign_user_op,
    random:        mock.random,
    audList:       mock.aud_list,
  };

  const t1 = Date.now();
  const proofOutput = await prove(CONFIG, request);
  console.log(`  done in ${((Date.now() - t1) / 1000).toFixed(1)}s`);
  console.log(`  proofs: ${proofOutput.proofs.length}, publicInputs: ${proofOutput.publicInputs.length}\n`);

  // ── 3. verify ────────────────────────────────────────────────────────────
  console.log('[3/3] verify...');
  for (let i = 0; i < proofOutput.proofs.length; i++) {
    const valid = await verify(setup.vkBytes, proofOutput.proofs[i], proofOutput.publicInputs[i]);
    console.log(`  proof[${i}]: ${valid ? 'valid ✓' : 'INVALID ✗'}`);
    if (!valid) process.exitCode = 1;
  }

  console.log('\nAll done.');
}

main().catch((e) => {
  console.error('Error:', e.message ?? e);
  process.exit(1);
});
