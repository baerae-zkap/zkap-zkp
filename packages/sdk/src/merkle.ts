import type { ProofRequest } from './types';

/**
 * Reorder a contract-format Merkle authentication path into the order the
 * circuit's witness generator consumes.
 *
 * On-chain `getMerklePath()` (BaseMerkleTree) returns the sibling hashes
 * bottom→root: `[leafSibling, inner_1, …, inner_top]`. The circuit keeps the
 * leaf sibling first but consumes the inner siblings top→bottom (arkworks
 * `Path::verify` walks the auth path in reverse), so the inner segment must be
 * reversed while `path[0]` stays put.
 *
 * Callers pass the on-chain `getMerklePath()` output verbatim — this
 * circuit-input detail is owned by the SDK, not the application.
 *
 * Idempotency: apply EXACTLY ONCE. Do not also reverse in the application
 * layer; a double reverse breaks the issuer-key Merkle-membership constraint.
 */
export function formatMerklePathForCircuit(
  contractPath: readonly string[],
): string[] {
  if (contractPath.length <= 1) return [...contractPath];
  return [contractPath[0], ...contractPath.slice(1).reverse()];
}

/**
 * Return a shallow copy of `request` whose every credential's `merklePath` is
 * formatted for the circuit via {@link formatMerklePathForCircuit}. The input
 * request is not mutated. Credentials without a `merklePath` are left as-is.
 */
export function withFormattedMerklePaths(request: ProofRequest): ProofRequest {
  return {
    ...request,
    credentials: request.credentials.map((credential) =>
      credential.merklePath
        ? {
            ...credential,
            merklePath: formatMerklePathForCircuit(credential.merklePath),
          }
        : credential,
    ),
  };
}
