package expo.modules.zkap

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.json.JSONArray
import org.json.JSONObject
import uniffi.zkap_uniffi_bindings.*

@OptIn(kotlin.ExperimentalUnsignedTypes::class)
class ZkapSdkModule : Module() {

    override fun definition() = ModuleDefinition {
        Name("ZkapSdk")

        AsyncFunction("generateHash") { inputJson: String ->
            try {
                val obj = JSONObject(inputJson)
                val messagesArr = obj.getJSONArray("messages")
                val messages = List(messagesArr.length()) { messagesArr.getString(it) }
                val result = generateHash(messages)
                JSONObject().put("result", result).toString()
            } catch (e: ZkapException) {
                throw ZkapError(e.message ?: "ZkapException")
            }
        }

        AsyncFunction("generateAudHash") { inputJson: String ->
            try {
                val obj = JSONObject(inputJson)
                val config = parseConfig(obj.getJSONObject("config"))
                val audArr = obj.getJSONArray("aud_list")
                val audList = List(audArr.length()) { audArr.getString(it) }
                val result = generateAudHash(config, audList)
                val audHashesArr = JSONArray(result.audHashes)
                JSONObject()
                    .put("aud_hashes", audHashesArr)
                    .put("h_aud_list", result.hAudList)
                    .toString()
            } catch (e: ZkapException) {
                throw ZkapError(e.message ?: "ZkapException")
            }
        }

        AsyncFunction("generateLeafHash") { inputJson: String ->
            try {
                val obj = JSONObject(inputJson)
                val config = parseConfig(obj.getJSONObject("config"))
                val iss = obj.getString("iss")
                val pkB64 = obj.getString("pk_b64")
                val result = generateLeafHash(config, iss, pkB64)
                JSONObject().put("result", result).toString()
            } catch (e: ZkapException) {
                throw ZkapError(e.message ?: "ZkapException")
            }
        }

        AsyncFunction("generateAnchor") { inputJson: String ->
            try {
                val obj = JSONObject(inputJson)
                val config = parseConfig(obj.getJSONObject("config"))
                val secretsArr = obj.getJSONArray("secrets")
                val secrets = List(secretsArr.length()) { i ->
                    val s = secretsArr.getJSONObject(i)
                    ZkapSecret(sub = s.getString("sub"), iss = s.getString("iss"), aud = s.getString("aud"))
                }
                val result = generateAnchor(config, secrets)
                JSONObject().put("evaluations", JSONArray(result.evaluations)).toString()
            } catch (e: ZkapException) {
                throw ZkapError(e.message ?: "ZkapException")
            }
        }

        AsyncFunction("prove") { inputJson: String ->
            try {
                val obj = JSONObject(inputJson)
                val config = parseConfig(obj.getJSONObject("config"))
                val req = obj.getJSONObject("request")

                val jwtsArr = req.getJSONArray("jwts")
                val jwts = List(jwtsArr.length()) { jwtsArr.getString(it) }

                val pkOpsArr = req.getJSONArray("pk_ops")
                val pkOps = List(pkOpsArr.length()) { pkOpsArr.getString(it) }

                val merklePathsArr = req.getJSONArray("merkle_paths")
                val merklePaths = List(merklePathsArr.length()) { i ->
                    val inner = merklePathsArr.getJSONArray(i)
                    List(inner.length()) { j -> inner.getString(j) }
                }

                val leafIndicesArr = req.getJSONArray("leaf_indices")
                val leafIndices = List(leafIndicesArr.length()) { leafIndicesArr.getLong(it).toULong() }

                val anchorEvalsArr = req.getJSONArray("anchor_evals")
                val anchorEvals = List(anchorEvalsArr.length()) { anchorEvalsArr.getString(it) }

                val audHashListArr = req.getJSONArray("aud_hash_list")
                val audHashList = List(audHashListArr.length()) { audHashListArr.getString(it) }

                val request = ZkapProofRequest(
                    pkPath = req.getString("pk_path"),
                    jwts = jwts,
                    pkOps = pkOps,
                    merklePaths = merklePaths,
                    leafIndices = leafIndices,
                    root = req.getString("root"),
                    anchorEvals = anchorEvals,
                    hanchor = req.getString("hanchor"),
                    hSignUserOp = req.getString("h_sign_user_op"),
                    random = req.getString("random"),
                    audHashList = audHashList
                )

                val output = prove(config, request)

                val proofsArr = JSONArray()
                for (proofList in output.proofs) {
                    proofsArr.put(JSONArray(proofList))
                }

                JSONObject()
                    .put("proofs", proofsArr)
                    .put("shared_inputs", JSONArray(output.sharedInputs))
                    .put("partial_rhs_list", JSONArray(output.partialRhsList))
                    .put("jwt_exp_list", JSONArray(output.jwtExpList))
                    .toString()
            } catch (e: ZkapException) {
                throw ZkapError(e.message ?: "ZkapException")
            }
        }
    }

    private fun parseConfig(obj: JSONObject): ZkapCircuitConfig {
        val claimsArr = obj.getJSONArray("claims")
        return ZkapCircuitConfig(
            maxJwtB64Len = obj.getLong("max_jwt_b64_len").toULong(),
            maxPayloadB64Len = obj.getLong("max_payload_b64_len").toULong(),
            maxAudLen = obj.getLong("max_aud_len").toULong(),
            maxExpLen = obj.getLong("max_exp_len").toULong(),
            maxIssLen = obj.getLong("max_iss_len").toULong(),
            maxNonceLen = obj.getLong("max_nonce_len").toULong(),
            maxSubLen = obj.getLong("max_sub_len").toULong(),
            n = obj.getLong("n").toULong(),
            k = obj.getLong("k").toULong(),
            treeHeight = obj.getLong("tree_height").toULong(),
            numAudienceLimit = obj.getLong("num_audience_limit").toULong(),
            claims = List(claimsArr.length()) { claimsArr.getString(it) },
            forbiddenString = obj.getString("forbidden_string")
        )
    }
}

class ZkapError(message: String) : Exception("[zkap] $message")
