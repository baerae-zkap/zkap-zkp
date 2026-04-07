/**
 * Basic hash example for @baerae/zkap-zkp-node (Node.js native)
 * Run: node examples/node/hash-basic.js
 */
const { generateHash, generateAnchor, generateAudHash } = require('@baerae/zkap-zkp-node');

const DEFAULT_CONFIG = {
  maxJwtB64Len: 1024,
  maxPayloadB64Len: 640,
  maxAudLen: 155,
  maxExpLen: 20,
  maxIssLen: 93,
  maxNonceLen: 93,
  maxSubLen: 93,
  n: 6,
  k: 3,
  treeHeight: 4,
  numAudienceLimit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbiddenString: 'forbidden',
};

// generateAnchor requires exactly n=6 secrets
const DEFAULT_SECRETS = Array.from({ length: 6 }, (_, i) => ({
  sub: `user-${i}`,
  iss: 'https://accounts.example.com',
  aud: 'my-client-id',
}));

async function main() {
  // generateHash: Poseidon hash
  const hash = await generateHash(['0x1', '0x2', '0x3']);
  console.log('generateHash:', hash);

  // generateAudHash
  const aud = await generateAudHash(DEFAULT_CONFIG, ['client-a', 'client-b']);
  console.log('generateAudHash hAudList:', aud.hAudList);
  console.log('generateAudHash audHashes[0]:', aud.audHashes[0]);

  // generateAnchor (n=6 secrets required)
  const anchor = await generateAnchor(DEFAULT_CONFIG, DEFAULT_SECRETS);
  console.log('generateAnchor evaluations[0]:', anchor.evaluations[0]);

  console.log('\nAll done.');
}

main().catch(console.error);
