// Re-export all public types and functions from the Node.js native bindings.
export type {
  JsSecret,
  JsCircuitConfig,
  JsAnchorResult,
  JsAudHashResult,
  JsProofRequest,
  JsProofOutput,
} from "@baerae/zkap-zkp-node";

export {
  generateHash,
  generateAnchor,
  generateAudHash,
  generateLeafHash,
  prove,
} from "@baerae/zkap-zkp-node";
