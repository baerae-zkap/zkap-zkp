import ExpoModulesCore

public class ZkapSdkModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ZkapSdk")

        // ──────────────────────────────────────────
        // generateHash
        // ──────────────────────────────────────────
        AsyncFunction("generateHash") { (inputJson: String) -> String in
            let data = inputJson.data(using: .utf8)!
            let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let messages = obj["messages"] as! [String]

            let result = try generateHash(messages: messages)

            let output: [String: Any] = ["result": result]
            let outData = try JSONSerialization.data(withJSONObject: output)
            return String(data: outData, encoding: .utf8)!
        }

        // ──────────────────────────────────────────
        // generateAudHash
        // ──────────────────────────────────────────
        AsyncFunction("generateAudHash") { (inputJson: String) -> String in
            let data = inputJson.data(using: .utf8)!
            let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let config = parseConfig(obj["config"] as! [String: Any])
            let audList = obj["aud_list"] as! [String]

            let result = try generateAudHash(config: config, audList: audList)

            let output: [String: Any] = [
                "aud_hashes": result.audHashes,
                "h_aud_list": result.hAudList
            ]
            let outData = try JSONSerialization.data(withJSONObject: output)
            return String(data: outData, encoding: .utf8)!
        }

        // ──────────────────────────────────────────
        // generateLeafHash
        // ──────────────────────────────────────────
        AsyncFunction("generateLeafHash") { (inputJson: String) -> String in
            let data = inputJson.data(using: .utf8)!
            let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let config = parseConfig(obj["config"] as! [String: Any])
            let iss = obj["iss"] as! String
            let pkB64 = obj["pk_b64"] as! String

            let result = try generateLeafHash(config: config, iss: iss, pkB64: pkB64)

            let output: [String: Any] = ["result": result]
            let outData = try JSONSerialization.data(withJSONObject: output)
            return String(data: outData, encoding: .utf8)!
        }

        // ──────────────────────────────────────────
        // generateAnchor
        // ──────────────────────────────────────────
        AsyncFunction("generateAnchor") { (inputJson: String) -> String in
            let data = inputJson.data(using: .utf8)!
            let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let config = parseConfig(obj["config"] as! [String: Any])
            let rawSecrets = obj["secrets"] as! [[String: Any]]
            let secrets = rawSecrets.map { s in
                ZkapSecret(
                    sub: s["sub"] as! String,
                    iss: s["iss"] as! String,
                    aud: s["aud"] as! String
                )
            }

            let result = try generateAnchor(config: config, secrets: secrets)

            let output: [String: Any] = ["evaluations": result.evaluations]
            let outData = try JSONSerialization.data(withJSONObject: output)
            return String(data: outData, encoding: .utf8)!
        }

        // ──────────────────────────────────────────
        // prove
        // ──────────────────────────────────────────
        AsyncFunction("prove") { (inputJson: String) -> String in
            let data = inputJson.data(using: .utf8)!
            let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let config = parseConfig(obj["config"] as! [String: Any])
            let req = obj["request"] as! [String: Any]

            let rawLeafIndices = req["leaf_indices"] as! [Any]
            let leafIndices: [UInt64] = rawLeafIndices.map { v in
                if let n = v as? Int { return UInt64(n) }
                if let n = v as? UInt64 { return n }
                return UInt64(v as! NSNumber)
            }

            let request = ZkapProofRequest(
                pkPath: req["pk_path"] as! String,
                jwts: req["jwts"] as! [String],
                pkOps: req["pk_ops"] as! [String],
                merklePaths: req["merkle_paths"] as! [[String]],
                leafIndices: leafIndices,
                root: req["root"] as! String,
                anchorEvals: req["anchor_evals"] as! [String],
                hanchor: req["hanchor"] as! String,
                hSignUserOp: req["h_sign_user_op"] as! String,
                random: req["random"] as! String,
                audHashList: req["aud_hash_list"] as! [String]
            )

            let result = try prove(config: config, request: request)

            let output: [String: Any] = [
                "proofs": result.proofs,
                "shared_inputs": result.sharedInputs,
                "partial_rhs_list": result.partialRhsList,
                "jwt_exp_list": result.jwtExpList
            ]
            let outData = try JSONSerialization.data(withJSONObject: output)
            return String(data: outData, encoding: .utf8)!
        }

    }
}

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

private func parseConfig(_ d: [String: Any]) -> ZkapCircuitConfig {
    ZkapCircuitConfig(
        maxJwtB64Len: UInt64(d["max_jwt_b64_len"] as! Int),
        maxPayloadB64Len: UInt64(d["max_payload_b64_len"] as! Int),
        maxAudLen: UInt64(d["max_aud_len"] as! Int),
        maxExpLen: UInt64(d["max_exp_len"] as! Int),
        maxIssLen: UInt64(d["max_iss_len"] as! Int),
        maxNonceLen: UInt64(d["max_nonce_len"] as! Int),
        maxSubLen: UInt64(d["max_sub_len"] as! Int),
        n: UInt64(d["n"] as! Int),
        k: UInt64(d["k"] as! Int),
        treeHeight: UInt64(d["tree_height"] as! Int),
        numAudienceLimit: UInt64(d["num_audience_limit"] as! Int),
        claims: d["claims"] as! [String],
        forbiddenString: d["forbidden_string"] as! String
    )
}

