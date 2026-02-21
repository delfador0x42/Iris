import Foundation

/// Analyzes file entropy to detect encrypted/ransomware-encrypted files.
/// Delegates to Rust FFI for Shannon entropy, chi-square, and Monte Carlo pi.
public struct EntropyAnalyzer {

    public struct Result: Sendable {
        public let entropy: Double
        public let chiSquare: Double
        public let monteCarloPIError: Double
        public let isEncrypted: Bool
    }

    /// Analyze a file for encryption indicators via Rust FFI.
    /// Returns nil if file is too small, unreadable, or a known format.
    public static func analyze(path: String) -> Result? {
        var out = IrisEntropyResult(entropy: 0, chi_square: 0, monte_carlo_pi_error: 0,
                                    is_encrypted: false, is_known_format: false)
        let rc = path.withCString { iris_file_entropy_full($0, &out) }
        guard rc == 0 else { return nil }
        return Result(
            entropy: out.entropy,
            chiSquare: out.chi_square,
            monteCarloPIError: out.monte_carlo_pi_error,
            isEncrypted: out.is_encrypted
        )
    }
}
