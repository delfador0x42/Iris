import Foundation

/// Swift wrapper for Rust batch operations (SHA256, entropy).
enum RustBatchOps {

    /// SHA256 hash a single file. Returns lowercase hex digest or nil on error.
    static func sha256(path: String) -> String? {
        var out: UnsafeMutablePointer<CChar>?
        let rc = path.withCString { iris_sha256_file($0, &out) }
        guard rc == 0, let ptr = out else { return nil }
        let result = String(cString: ptr)
        iris_free_string(ptr)
        return result
    }

    /// Shannon entropy of a file (0.0–8.0). Returns nil on error.
    static func entropy(path: String) -> Double? {
        var out: Double = 0
        let rc = path.withCString { iris_file_entropy($0, &out) }
        guard rc == 0 else { return nil }
        return out
    }

    /// Full entropy analysis result from Rust.
    struct EntropyAnalysis {
        let entropy: Double
        let chiSquare: Double
        let monteCarloPIError: Double
        let isEncrypted: Bool
    }

    /// Full entropy analysis: Shannon entropy, chi-square, Monte Carlo pi, encrypted detection.
    /// Returns nil if file is too small, unreadable, or a known format (image/archive/PDF).
    static func entropyAnalysis(path: String) -> EntropyAnalysis? {
        var out = IrisEntropyResult(entropy: 0, chi_square: 0, monte_carlo_pi_error: 0,
                                    is_encrypted: false, is_known_format: false)
        let rc = path.withCString { iris_file_entropy_full($0, &out) }
        guard rc == 0 else { return nil }
        return EntropyAnalysis(
            entropy: out.entropy, chiSquare: out.chi_square,
            monteCarloPIError: out.monte_carlo_pi_error, isEncrypted: out.is_encrypted)
    }

    /// Batch SHA256: hash multiple files in one call. Returns array of hex digests.
    /// Empty string for files that failed.
    static func batchSHA256(paths: [String]) -> [String] {
        guard !paths.isEmpty else { return [] }
        let cPaths = paths.map { strdup($0) }
        defer { cPaths.forEach { free($0) } }
        var out = IrisCStringArray(items: nil, count: 0)
        let ptrs = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: paths.count)
        defer { ptrs.deallocate() }
        for (i, p) in cPaths.enumerated() { ptrs[i] = p }

        let rc = ptrs.withMemoryRebound(to: UnsafePointer<CChar>?.self, capacity: paths.count) {
            iris_batch_sha256($0, paths.count, &out)
        }
        defer { iris_batch_sha256_free(&out) }
        guard rc == 0, out.count > 0, let items = out.items else { return [] }
        guard out.count == paths.count else {
            assertionFailure("Rust FFI returned \(out.count) results for \(paths.count) paths")
            return []
        }

        return (0..<out.count).map { i in
            guard let cstr = items.advanced(by: i).pointee else { return "" }
            return String(cString: cstr)
        }
    }
}
