import Foundation

/// Cross-scanner correlation — detects multi-stage attack chains
/// by analyzing findings across different scanners for the same process/entity.
public struct CorrelationEngine: Sendable {

  /// A correlated finding linking multiple scanners.
  public struct Correlation: Identifiable, Sendable {
    public let id: UUID
    public let name: String
    public let description: String
    public let scannerIds: [String]
    public let anomalies: [ProcessAnomaly]
    public let severity: AnomalySeverity
    public let mitreChain: String
  }

  /// Analyze scanner results for cross-scanner patterns.
  public static func correlate(_ results: [ScannerResult]) -> [Correlation] {
    var correlations: [Correlation] = []
    let byProcess = groupByProcess(results)

    for (processName, anomalies) in byProcess {
      let scannerIds = Set(anomalies.compactMap { findScanner($0, in: results) })
      guard scannerIds.count >= 2 else { continue }

      // Credential access + network = exfiltration chain
      if let c = checkExfiltrationChain(processName, anomalies, scannerIds) {
        correlations.append(c)
      }
      // Hidden + stealth = rootkit behavior
      if let c = checkRootkitChain(processName, anomalies, scannerIds) {
        correlations.append(c)
      }
      // Persistence + unsigned = malware install
      if let c = checkMalwareInstall(processName, anomalies, scannerIds) {
        correlations.append(c)
      }
      // Multi-scanner hit (3+) on same process = high confidence threat
      if scannerIds.count >= 3 {
        correlations.append(Correlation(
          id: UUID(), name: "Multi-Scanner Threat",
          description: "\(processName) flagged by \(scannerIds.count) scanners",
          scannerIds: Array(scannerIds), anomalies: anomalies,
          severity: .high,
          mitreChain: anomalies.compactMap(\.mitreID).joined(separator: " → ")))
      }
    }
    return correlations
  }

  // MARK: - Chain Detectors

  private static func checkExfiltrationChain(
    _ proc: String, _ anomalies: [ProcessAnomaly], _ ids: Set<String>
  ) -> Correlation? {
    let hasCredAccess = ids.contains("credential_access")
    let hasNetwork = ids.contains("network_anomaly") || ids.contains("cloud_c2")
    guard hasCredAccess && hasNetwork else { return nil }
    return Correlation(
      id: UUID(), name: "Credential Exfiltration Chain",
      description: "\(proc): credential access + suspicious network activity",
      scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
      mitreChain: "T1555 → T1567")
  }

  private static func checkRootkitChain(
    _ proc: String, _ anomalies: [ProcessAnomaly], _ ids: Set<String>
  ) -> Correlation? {
    let hasHidden = ids.contains("hidden_process") || ids.contains("stealth")
    let hasKernel = ids.contains("kext") || ids.contains("kernel_integrity")
    guard hasHidden && hasKernel else { return nil }
    return Correlation(
      id: UUID(), name: "Rootkit Behavior",
      description: "\(proc): hidden process + kernel manipulation",
      scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
      mitreChain: "T1014 → T1547.006")
  }

  private static func checkMalwareInstall(
    _ proc: String, _ anomalies: [ProcessAnomaly], _ ids: Set<String>
  ) -> Correlation? {
    let hasPersistence = ids.contains("persistence")
    let hasBinary = ids.contains("binary_integrity") || ids.contains("dylib_hijack")
    guard hasPersistence && hasBinary else { return nil }
    return Correlation(
      id: UUID(), name: "Malware Installation",
      description: "\(proc): persistence + unsigned/hijacked binary",
      scannerIds: Array(ids), anomalies: anomalies, severity: .high,
      mitreChain: "T1547 → T1574")
  }

  // MARK: - Helpers

  private static func groupByProcess(
    _ results: [ScannerResult]
  ) -> [String: [ProcessAnomaly]] {
    var map: [String: [ProcessAnomaly]] = [:]
    for r in results {
      for a in r.anomalies where !a.processName.isEmpty {
        map[a.processName, default: []].append(a)
      }
    }
    return map
  }

  private static func findScanner(
    _ anomaly: ProcessAnomaly, in results: [ScannerResult]
  ) -> String? {
    results.first { $0.anomalies.contains(where: { $0.id == anomaly.id }) }?.id
  }
}
