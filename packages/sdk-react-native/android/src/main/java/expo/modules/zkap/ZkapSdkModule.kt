package expo.modules.zkap

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ZkapSdkModule : Module() {

    // Load the native Rust library
    companion object {
        init {
            System.loadLibrary("zkap_zkp_rn")
        }

        // JNI declarations — implemented in Rust via C ABI
        @JvmStatic external fun zkap_generate_hash(inputJson: String): String
        @JvmStatic external fun zkap_generate_anchor(inputJson: String): String
        @JvmStatic external fun zkap_generate_aud_hash(inputJson: String): String
        @JvmStatic external fun zkap_generate_leaf_hash(inputJson: String): String
        @JvmStatic external fun zkap_prove(inputJson: String): String
    }

    override fun definition() = ModuleDefinition {
        Name("ZkapSdk")

        // ──────────────────────────────────────────
        // generateHash
        // ──────────────────────────────────────────
        AsyncFunction("generateHash") { inputJson: String ->
            val result = zkap_generate_hash(inputJson)
            unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // generateAnchor
        // ──────────────────────────────────────────
        AsyncFunction("generateAnchor") { inputJson: String ->
            val result = zkap_generate_anchor(inputJson)
            unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // generateAudHash
        // ──────────────────────────────────────────
        AsyncFunction("generateAudHash") { inputJson: String ->
            val result = zkap_generate_aud_hash(inputJson)
            unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // generateLeafHash
        // ──────────────────────────────────────────
        AsyncFunction("generateLeafHash") { inputJson: String ->
            val result = zkap_generate_leaf_hash(inputJson)
            unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // prove
        // ──────────────────────────────────────────
        AsyncFunction("prove") { inputJson: String ->
            val result = zkap_prove(inputJson)
            unwrapResult(result)
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    /**
     * Parse the JSON string returned by the Rust FFI.
     * Throws if the result contains an "error" field.
     */
    @Suppress("UNCHECKED_CAST")
    private fun unwrapResult(json: String): String {
        try {
            val obj = org.json.JSONObject(json)
            if (obj.has("error")) {
                throw ZkapException(obj.getString("error"))
            }
        } catch (e: org.json.JSONException) {
            // Not a JSON object — return as-is (shouldn't happen in normal usage)
        }
        return json
    }
}

class ZkapException(message: String) : Exception("[zkap] $message")
