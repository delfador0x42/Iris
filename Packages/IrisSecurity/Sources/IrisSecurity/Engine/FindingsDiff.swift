import Foundation

/// Diff between two scan results showing new, resolved, and unchanged findings.
public struct FindingsDiff: Sendable {
  public let newFindings: [ProcessAnomaly]
  public let resolvedFindings: [ProcessAnomaly]
  public let unchangedCount: Int

  public var hasChanges: Bool { !newFindings.isEmpty || !resolvedFindings.isEmpty }

  /// Compute diff between current and previous scan results.
  /// Matches on processName + technique to identify same finding across scans.
  public static func compute(
    current: ThreatScanResult, previous: ThreatScanResult
  ) -> FindingsDiff {
    let currentKeys = Set(current.anomalies.map { key(for: $0) })
    let previousKeys = Set(previous.anomalies.map { key(for: $0) })

    let newKeys = currentKeys.subtracting(previousKeys)
    let resolvedKeys = previousKeys.subtracting(currentKeys)

    return FindingsDiff(
      newFindings: current.anomalies.filter { newKeys.contains(key(for: $0)) },
      resolvedFindings: previous.anomalies.filter { resolvedKeys.contains(key(for: $0)) },
      unchangedCount: currentKeys.intersection(previousKeys).count)
  }

  /// Stable key for deduplication — same process + technique = same finding.
  private static func key(for a: ProcessAnomaly) -> String {
    "\(a.processName)|\(a.technique)"
  }
}
