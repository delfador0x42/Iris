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
        guard rc == 0, out.count > 0, let items = out.items else { return [] }
        defer { iris_batch_sha256_free(&out) }

        return (0..<out.count).map { i in
            guard let cstr = items.advanced(by: i).pointee else { return "" }
            return String(cString: cstr)
        }
    }
}
