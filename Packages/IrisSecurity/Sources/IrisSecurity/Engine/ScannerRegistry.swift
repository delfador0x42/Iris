import Foundation

/// Execution tier — determines scan ordering and concurrency.
/// Fast scanners run first so users see initial results quickly.
public enum ScannerTier: Int, Comparable, Sendable {
  case fast = 0    // In-memory process inspection, snapshot-only
  case medium = 1  // Filesystem reads, plist parsing, sqlite queries
  case slow = 2    // codesign verification, network calls, docker ls

  public static func < (lhs: ScannerTier, rhs: ScannerTier) -> Bool {
    lhs.rawValue < rhs.rawValue
  }

  public var label: String {
    switch self {
    case .fast: return "fast"
    case .medium: return "medium"
    case .slow: return "slow"
    }
  }
}

/// Context passed to every scanner — shared resources captured once per scan.
public struct ScanContext: Sendable {
  public let snapshot: ProcessSnapshot
  public let connections: [NetworkConnection]
}

/// A registered scanner with metadata and execution closure.
public struct ScannerEntry: Identifiable, Sendable {
  public let id: String
  public let name: String
  public let tier: ScannerTier
  public let run: @Sendable (ScanContext) async -> [ProcessAnomaly]
}

/// Result of a single scanner execution with timing data.
public struct ScannerResult: Identifiable, Sendable {
  public let id: String
  public let name: String
  public let tier: ScannerTier
  public let anomalies: [ProcessAnomaly]
  public let duration: TimeInterval
  public let timestamp: Date
}
