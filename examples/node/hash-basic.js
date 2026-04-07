/**
 * Basic hash example for @baerae/zkap-zkp (Node.js)
 * Run: node examples/node/hash-basic.js
 */
const { generateHash, generateAnchor, generateAudHash, generateLeafHash } = require('@baerae/zkap-zkp');

async function main() {
  // generateHash: Poseidon hash of field elements
  const hash = await generateHash(['0x1', '0x2', '0x3']);
  console.log('generateHash:', hash);

  // generateAnchor: threshold anchor from JWT secrets
  const config = {
    maxJwtB64Len: 1116, maxPayloadB64Len: 744, maxAudLen: 248,
    maxExpLen: 31, maxIssLen: 248, maxNonceLen: 93, maxSubLen: 248,
    n: 121, k: 17, treeHeight: 6, numAudienceLimit: 10,
    claims: ['sub', 'iss', 'aud', 'exp', 'nonce'],
    forbiddenString: 'forbidden',
  };
  const anchor = await generateAnchor(config, [
    { sub: 'user1', iss: 'https://issuer.example', aud: 'client-id' },
  ]);
  console.log('generateAnchor evaluations:', anchor.evaluations.length);
}

main().catch(console.error);
