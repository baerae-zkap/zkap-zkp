import init, {
  generateHash,
  generateAnchor,
  generateAudHash,
} from '@baerae/zkap-zkp-wasm';

const out = document.getElementById('output');
const log = (msg) => { out.textContent += msg + '\n'; };

const DEFAULT_CONFIG = {
  maxJwtB64Len: 1024, maxPayloadB64Len: 640, maxAudLen: 155,
  maxExpLen: 20, maxIssLen: 93, maxNonceLen: 93, maxSubLen: 93,
  n: 6, k: 3, treeHeight: 4, numAudienceLimit: 5,
  claims: ['aud', 'exp', 'iss', 'nonce', 'sub'],
  forbiddenString: 'forbidden',
};

// generateAnchor requires exactly n=6 secrets
const DEFAULT_SECRETS = Array.from({ length: 6 }, (_, i) => ({
  sub: `user-${i}`,
  iss: 'https://accounts.example.com',
  aud: 'my-client-id',
}));

try {
  await init();
  log('WASM initialized\n');

  const hash = generateHash(['0x1', '0x2', '0x3']);
  log(`generateHash(['0x1','0x2','0x3'])\n  → ${hash}\n`);

  const audResult = generateAudHash(DEFAULT_CONFIG, ['client-a', 'client-b']);
  log(`generateAudHash\n  hAudList     → ${audResult.hAudList}\n  audHashes[0] → ${audResult.audHashes[0]}\n`);

  const anchor = generateAnchor(DEFAULT_CONFIG, DEFAULT_SECRETS);
  log(`generateAnchor (n=6)\n  evaluations[0] → ${anchor.evaluations[0]}\n`);

  log('All done.');
} catch (e) {
  console.error('Full error:', e);
  out.textContent = `Error: ${e?.message ?? String(e)}`;
}
