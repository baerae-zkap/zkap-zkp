// Re-export all public types and functions from the Node.js native bindings.
export type {
  JsSecret,
  JsCircuitConfig,
  JsAnchorResult,
  JsAudHashResult,
  JsSetupOutput,
  JsProofRequest,
  JsProofOutput,
} from "@baerae/zkap-zkp-node";

export {
  generateHash,
  generateAnchor,
  generateAudHash,
  generateLeafHash,
  groth16Setup,
  prove,
  verify,
} from "@baerae/zkap-zkp-node";
