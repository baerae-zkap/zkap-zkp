// Stub for `@baerae/zkap-zkp-node` so the Node facade can be imported in tests
// without loading the native NAPI binary. download/staging logic does not touch
// these functions; they only back prove/verify/loadRelease/prepareProver.
const notUsed = (name: string) => () => {
  throw new Error(`[test] @baerae/zkap-zkp-node.${name} should not be called by download tests`);
};

export const generateAnchor = notUsed('generateAnchor');
export const generateAudHash = notUsed('generateAudHash');
export const generateHash = notUsed('generateHash');
export const generateLeafHash = notUsed('generateLeafHash');
export const loadRelease = notUsed('loadRelease');
export const prepareProver = notUsed('prepareProver');
export const prove = notUsed('prove');
export const verify = notUsed('verify');
