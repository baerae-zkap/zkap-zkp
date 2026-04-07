package expo.modules.zkap

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ZkapSdkModule : Module() {

    // Load the native Rust library (built as libzkap_zkp_rn.so)
    companion object {
        init {
            System.loadLibrary("zkap_zkp_rn")
        }

        // JNI-compatible native methods (no underscores → no name-mangling issues).
        // Corresponding Rust symbol: Java_expo_modules_zkap_ZkapSdkModule_native<X>
        // Each JNI wrapper in Rust calls the C-ABI function, copies the result into
        // a Java String, and frees the Rust allocation — no memory leak.
        @JvmStatic external fun nativeGenerateHash(inputJson: String): String
        @JvmStatic external fun nativeGenerateAnchor(inputJson: String): String
        @JvmStatic external fun nativeGenerateAudHash(inputJson: String): String
        @JvmStatic external fun nativeGenerateLeafHash(inputJson: String): String
        @JvmStatic external fun nativeProve(inputJson: String): String
    }

    override fun definition() = ModuleDefinition {
        Name("ZkapSdk")

        AsyncFunction("generateHash") { inputJson: String ->
            unwrapResult(nativeGenerateHash(inputJson))
        }

        AsyncFunction("generateAnchor") { inputJson: String ->
            unwrapResult(nativeGenerateAnchor(inputJson))
        }

        AsyncFunction("generateAudHash") { inputJson: String ->
            unwrapResult(nativeGenerateAudHash(inputJson))
        }

        AsyncFunction("generateLeafHash") { inputJson: String ->
            unwrapResult(nativeGenerateLeafHash(inputJson))
        }

        AsyncFunction("prove") { inputJson: String ->
            unwrapResult(nativeProve(inputJson))
        }
    }

    /** Parse JSON result from Rust FFI. Throws if the result contains an "error" field. */
    @Suppress("UNCHECKED_CAST")
    private fun unwrapResult(json: String): String {
        try {
            val obj = org.json.JSONObject(json)
            if (obj.has("error")) {
                throw ZkapException(obj.getString("error"))
            }
        } catch (e: org.json.JSONException) {
            // Not a JSON object — return as-is
        }
        return json
    }
}

class ZkapException(message: String) : Exception("[zkap] $message")
