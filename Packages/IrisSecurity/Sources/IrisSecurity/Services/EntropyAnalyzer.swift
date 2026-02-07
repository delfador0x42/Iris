import Foundation

/// Analyzes file entropy to detect encrypted/ransomware-encrypted files
public struct EntropyAnalyzer {
    /// Thresholds for encryption detection (from RansomWhere research)
    static let entropyThreshold: Double = 7.95
    static let monteCarloErrorThreshold: Double = 1.5
    static let chiSquareThreshold: Double = 400.0
    static let minFileSize = 1024
    static let readChunkSize = 3 * 1024 * 1024 // 3 MB

    /// Known compressed/image file magic bytes to skip
    private static let imageMagics: [(Data, String)] = [
        (Data([0x89, 0x50, 0x4E, 0x47]), "PNG"),
        (Data([0xFF, 0xD8, 0xFF, 0xE0]), "JPEG"),
        (Data([0xFF, 0xD8, 0xFF, 0xDB]), "JPEG"),
        (Data([0x47, 0x49, 0x46, 0x38]), "GIF"),
        (Data([0x49, 0x49, 0x2A, 0x00]), "TIFF"),
        (Data([0x4D, 0x4D, 0x00, 0x2A]), "TIFF"),
    ]

    /// Result of entropy analysis
    public struct Result: Sendable {
        public let entropy: Double        // Bits per byte (0-8)
        public let chiSquare: Double      // Chi-square statistic
        public let monteCarloPIError: Double // Monte Carlo pi estimation error %
        public let isEncrypted: Bool
    }

    /// Analyze a file for encryption indicators
    public static func analyze(path: String) -> Result? {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let size = attrs[.size] as? Int,
              size >= minFileSize else {
            return nil
        }

        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { handle.closeFile() }

        let data = handle.readData(ofLength: readChunkSize)
        guard data.count >= minFileSize else { return nil }

        // Skip known image/compressed formats
        if isKnownFormat(data) { return nil }

        let bytes = [UInt8](data)
        let entropy = shannonEntropy(bytes)
        let chiSquare = chiSquareTest(bytes)
        let piError = monteCarloPI(bytes)

        let isEncrypted = entropy >= entropyThreshold &&
                          piError <= monteCarloErrorThreshold &&
                          !(piError > 0.5 && chiSquare > chiSquareThreshold)

        return Result(
            entropy: entropy,
            chiSquare: chiSquare,
            monteCarloPIError: piError,
            isEncrypted: isEncrypted
        )
    }

    /// Shannon entropy: bits per byte (0 = uniform, 8 = maximum randomness)
    static func shannonEntropy(_ bytes: [UInt8]) -> Double {
        var counts = [Int](repeating: 0, count: 256)
        for byte in bytes { counts[Int(byte)] += 1 }

        let length = Double(bytes.count)
        var entropy = 0.0
        for count in counts where count > 0 {
            let p = Double(count) / length
            entropy -= p * log2(p)
        }
        return entropy
    }

    /// Chi-square test for uniform distribution
    static func chiSquareTest(_ bytes: [UInt8]) -> Double {
        var counts = [Double](repeating: 0.0, count: 256)
        for byte in bytes { counts[Int(byte)] += 1.0 }

        let expected = Double(bytes.count) / 256.0
        var chiSq = 0.0
        for count in counts {
            let diff = count - expected
            chiSq += (diff * diff) / expected
        }
        return chiSq
    }

    /// Monte Carlo pi estimation — random-looking data estimates pi accurately
    static func monteCarloPI(_ bytes: [UInt8]) -> Double {
        guard bytes.count >= 12 else { return 100.0 }
        var inside = 0
        var total = 0

        // Use pairs of 3-byte values as coordinates
        var i = 0
        while i + 5 < bytes.count {
            let x = Double(Int(bytes[i]) << 16 | Int(bytes[i+1]) << 8 | Int(bytes[i+2]))
            let y = Double(Int(bytes[i+3]) << 16 | Int(bytes[i+4]) << 8 | Int(bytes[i+5]))
            let maxVal = Double(0xFFFFFF)

            let nx = x / maxVal
            let ny = y / maxVal

            if nx * nx + ny * ny <= 1.0 {
                inside += 1
            }
            total += 1
            i += 6
        }

        guard total > 0 else { return 100.0 }
        let estimatedPi = 4.0 * Double(inside) / Double(total)
        return 100.0 * abs(Double.pi - estimatedPi) / Double.pi
    }

    private static func isKnownFormat(_ data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        let header = data.prefix(4)

        for (magic, _) in imageMagics {
            if header.starts(with: magic) { return true }
        }

        // Gzip: 1F 8B 08
        if data.count >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08 {
            return true
        }

        // ZIP: 50 4B 03 04
        if header == Data([0x50, 0x4B, 0x03, 0x04]) { return true }

        // PDF: 25 50 44 46
        if header == Data([0x25, 0x50, 0x44, 0x46]) { return true }

        return false
    }
}
