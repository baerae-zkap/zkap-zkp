// Ambient shorthand declaration for the OPTIONAL expo-file-system peer.
//
// `react-native.ts` must import the literal specifier
// 'expo-file-system/legacy' so Metro can statically bundle it (see
// loadExpoFileSystem), but the SDK itself does not depend on
// expo-file-system, so the tsup dts build cannot resolve the module's
// types. This shorthand declares the module as `any`; the call site
// narrows it with an explicit `as ExpoFileSystem` cast.
declare module 'expo-file-system/legacy';
