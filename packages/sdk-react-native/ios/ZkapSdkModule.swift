import ExpoModulesCore

public class ZkapSdkModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ZkapSdk")

        // ──────────────────────────────────────────
        // generateHash
        // ──────────────────────────────────────────
        AsyncFunction("generateHash") { (inputJson: String) -> String in
            guard let cInput = inputJson.cString(using: .utf8) else {
                throw ZkapError.invalidInput("Failed to encode inputJson as UTF-8")
            }
            let result = zkap_generate_hash(cInput)
            defer { zkap_free_string(result) }
            return try ZkapSdkModule.unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // generateAnchor
        // ──────────────────────────────────────────
        AsyncFunction("generateAnchor") { (inputJson: String) -> String in
            guard let cInput = inputJson.cString(using: .utf8) else {
                throw ZkapError.invalidInput("Failed to encode inputJson as UTF-8")
            }
            let result = zkap_generate_anchor(cInput)
            defer { zkap_free_string(result) }
            return try ZkapSdkModule.unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // generateAudHash
        // ──────────────────────────────────────────
        AsyncFunction("generateAudHash") { (inputJson: String) -> String in
            guard let cInput = inputJson.cString(using: .utf8) else {
                throw ZkapError.invalidInput("Failed to encode inputJson as UTF-8")
            }
            let result = zkap_generate_aud_hash(cInput)
            defer { zkap_free_string(result) }
            return try ZkapSdkModule.unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // generateLeafHash
        // ──────────────────────────────────────────
        AsyncFunction("generateLeafHash") { (inputJson: String) -> String in
            guard let cInput = inputJson.cString(using: .utf8) else {
                throw ZkapError.invalidInput("Failed to encode inputJson as UTF-8")
            }
            let result = zkap_generate_leaf_hash(cInput)
            defer { zkap_free_string(result) }
            return try ZkapSdkModule.unwrapResult(result)
        }

        // ──────────────────────────────────────────
        // prove
        // ──────────────────────────────────────────
        AsyncFunction("prove") { (inputJson: String) -> String in
            guard let cInput = inputJson.cString(using: .utf8) else {
                throw ZkapError.invalidInput("Failed to encode inputJson as UTF-8")
            }
            let result = zkap_prove(cInput)
            defer { zkap_free_string(result) }
            return try ZkapSdkModule.unwrapResult(result)
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    /// Convert a raw C string pointer returned by the Rust FFI into a Swift String.
    /// Throws ZkapError.rustError if the JSON contains an "error" field.
    private static func unwrapResult(_ ptr: UnsafeMutablePointer<CChar>?) throws -> String {
        guard let ptr = ptr else {
            throw ZkapError.rustError("Rust FFI returned null pointer")
        }
        let json = String(cString: ptr)

        // Check for error response: {"error": "..."}
        if let data = json.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let errMsg = obj["error"] as? String {
            throw ZkapError.rustError(errMsg)
        }

        return json
    }
}

// ──────────────────────────────────────────────────────────────────
// Error types
// ──────────────────────────────────────────────────────────────────

enum ZkapError: Error, CustomStringConvertible {
    case invalidInput(String)
    case rustError(String)

    var description: String {
        switch self {
        case .invalidInput(let msg): return "[zkap] Invalid input: \(msg)"
        case .rustError(let msg): return "[zkap] Rust error: \(msg)"
        }
    }
}
