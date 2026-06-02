// Stub for `@baerae/zkap-zkp-react-native` so the React Native facade can be
// imported in a plain Node test process (the real package imports `react-native`).
// download/staging logic does not call these; they back prove/generate*.
const notUsed = (name: string) => () => {
  throw new Error(`[test] @baerae/zkap-zkp-react-native.${name} should not be called by download tests`);
};

export const generateAnchor = notUsed('generateAnchor');
export const generateAudHash = notUsed('generateAudHash');
export const generateHash = notUsed('generateHash');
export const generateLeafHash = notUsed('generateLeafHash');
export const prove = notUsed('prove');
