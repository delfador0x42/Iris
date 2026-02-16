import Foundation

/// Extract printable ASCII strings from binary data and classify suspicious patterns.
/// No shell-out to /usr/bin/strings — reads raw bytes directly.
public enum StringsExtractor {

  /// Minimum printable run length to consider
  private static let minLength = 6
  /// Max bytes to scan (2 MB)
  private static let maxScan = 2 * 1024 * 1024

  /// Extract and classify suspicious strings from a binary at path.
  public static func extract(path: String) -> [BinaryAnalysis.SuspiciousString] {
    guard let handle = FileHandle(forReadingAtPath: path) else { return [] }
    defer { handle.closeFile() }
    let data = handle.readData(ofLength: maxScan)
    let bytes = [UInt8](data)

    var suspicious: [BinaryAnalysis.SuspiciousString] = []
    var seen = Set<String>()
    var run = [UInt8]()

    for byte in bytes {
      if byte >= 0x20 && byte < 0x7F {
        run.append(byte)
      } else {
        if run.count >= minLength, let s = String(bytes: run, encoding: .ascii) {
          if !seen.contains(s), let cat = classify(s) {
            seen.insert(s)
            suspicious.append(.init(value: s, category: cat))
          }
        }
        run.removeAll(keepingCapacity: true)
      }
    }
    // flush trailing run
    if run.count >= minLength, let s = String(bytes: run, encoding: .ascii) {
      if !seen.contains(s), let cat = classify(s) {
        suspicious.append(.init(value: s, category: cat))
      }
    }

    // Cap at 50, prioritized by category severity
    return Array(suspicious.sorted { priority($0.category) < priority($1.category) }.prefix(50))
  }

  private static func classify(_ s: String) -> StringCategory? {
    let low = s.lowercased()
    // C2 patterns (most suspicious)
    if c2Patterns.contains(where: { low.contains($0) }) { return .c2Pattern }
    // Shell commands
    if shellPatterns.contains(where: { low.contains($0) }) { return .shellCmd }
    // Crypto APIs
    if cryptoPatterns.contains(where: { low.contains($0) }) { return .cryptoAPI }
    // URLs
    if low.contains("http://") || low.contains("https://") { return .url }
    // IP addresses (simple heuristic: 4 dot-separated octets)
    if isIPAddress(s) { return .ipAddress }
    return nil
  }

  private static let c2Patterns = [
    "beacon", "payload", "stager", "meterpreter", "reverse_tcp",
    "cobalt", "empire", "sliver", "mythic", "havoc",
    "c2profile", "implant", "exfil",
  ]

  private static let shellPatterns = [
    "/bin/sh", "/bin/bash", "/bin/zsh", "system(", "popen(",
    "execve", "posix_spawn", "NSTask", "Process(",
  ]

  private static let cryptoPatterns = [
    "cccrypt", "seckey", "kccencrypt", "kccdecrypt",
    "cchmac", "commoncrypto", "security.framework",
  ]

  private static func isIPAddress(_ s: String) -> Bool {
    let parts = s.split(separator: ".")
    guard parts.count == 4 else { return false }
    return parts.allSatisfy { p in
      if let n = Int(p) { return n >= 0 && n <= 255 }
      return false
    }
  }

  private static func priority(_ cat: StringCategory) -> Int {
    switch cat {
    case .c2Pattern: return 0
    case .shellCmd: return 1
    case .cryptoAPI: return 2
    case .url: return 3
    case .ipAddress: return 4
    }
  }
}
