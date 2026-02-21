import Foundation

/// Cross-scanner correlation — detects multi-stage attack chains
/// by analyzing findings across different scanners for the same process/entity.
public struct CorrelationEngine: Sendable {

  /// A correlated finding linking multiple scanners.
  public struct Correlation: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let description: String
    public let scannerIds: [String]
    public let anomalies: [ProcessAnomaly]
    public let severity: AnomalySeverity
    public let mitreChain: String
  }

  /// Analyze scanner results for cross-scanner patterns.
  /// Groups by PID (not processName) to avoid false correlations
  /// across distinct instances of the same binary (e.g. multiple Chrome helpers).
  public static func correlate(_ results: [ScannerResult]) -> [Correlation] {
    var correlations: [Correlation] = []
    let byProcess = groupByProcess(results)
    // Build reverse map: anomaly ID → scanner ID (O(1) lookup instead of O(n*m))
    let anomalyToScanner = buildReverseMap(results)

    for (_, anomalies) in byProcess {
      let processName = anomalies.first?.processName ?? "Unknown"
      let scannerIds = Set(anomalies.compactMap { anomalyToScanner[$0.id] })
      guard scannerIds.count >= 2 else { continue }

      for chain in chainChecks {
        if let c = chain(processName, anomalies, scannerIds) {
          correlations.append(c)
        }
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

  private typealias ChainCheck = (String, [ProcessAnomaly], Set<String>) -> Correlation?

  private static let chainChecks: [ChainCheck] = [
    // Credential access + network = exfiltration
    { proc, anomalies, ids in
      guard ids.contains("credential_access"),
            ids.contains("network_anomaly") || ids.contains("cloud_c2") else { return nil }
      return Correlation(id: UUID(), name: "Credential Exfiltration Chain",
        description: "\(proc): credential access + suspicious network",
        scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
        mitreChain: "T1555 → T1567")
    },
    // Hidden + kernel = rootkit
    { proc, anomalies, ids in
      guard ids.contains("hidden_process") || ids.contains("stealth"),
            ids.contains("kext") || ids.contains("kernel_integrity") else { return nil }
      return Correlation(id: UUID(), name: "Rootkit Behavior",
        description: "\(proc): hidden process + kernel manipulation",
        scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
        mitreChain: "T1014 → T1547.006")
    },
    // Persistence + unsigned binary = malware install
    { proc, anomalies, ids in
      guard ids.contains("persistence") || ids.contains("persistence_monitor"),
            ids.contains("binary_integrity") || ids.contains("dylib_hijack") else { return nil }
      return Correlation(id: UUID(), name: "Malware Installation",
        description: "\(proc): persistence + unsigned/hijacked binary",
        scannerIds: Array(ids), anomalies: anomalies, severity: .high,
        mitreChain: "T1547 → T1574")
    },
    // Defense evasion: stealth + security tool evasion
    { proc, anomalies, ids in
      guard ids.contains("stealth") || ids.contains("hidden_process"),
            ids.contains("security_evasion") || ids.contains("process_integrity") else { return nil }
      return Correlation(id: UUID(), name: "Defense Evasion Chain",
        description: "\(proc): hiding + security tool evasion",
        scannerIds: Array(ids), anomalies: anomalies, severity: .high,
        mitreChain: "T1562 → T1070")
    },
    // Privilege escalation: auth_db + persistence
    { proc, anomalies, ids in
      guard ids.contains("auth_db"),
            ids.contains("persistence") || ids.contains("persistence_monitor") || ids.contains("kext") else { return nil }
      return Correlation(id: UUID(), name: "Privilege Escalation Chain",
        description: "\(proc): authorization abuse + persistence",
        scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
        mitreChain: "T1548 → T1547")
    },
    // C2 establishment: DNS tunneling/covert channel + cloud C2
    { proc, anomalies, ids in
      guard ids.contains("dns_tunnel") || ids.contains("covert_channel"),
            ids.contains("cloud_c2") || ids.contains("network_anomaly") else { return nil }
      return Correlation(id: UUID(), name: "C2 Establishment",
        description: "\(proc): covert channel + network C2",
        scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
        mitreChain: "T1071 → T1573")
    },
    // Injection chain: thread anomaly + dyld env + process integrity
    { proc, anomalies, ids in
      guard ids.contains("thread_anomaly") || ids.contains("dyld_env"),
            ids.contains("process_integrity") || ids.contains("memory") else { return nil }
      return Correlation(id: UUID(), name: "Code Injection Chain",
        description: "\(proc): injection indicators + integrity violation",
        scannerIds: Array(ids), anomalies: anomalies, severity: .high,
        mitreChain: "T1055 → T1574.006")
    },
    // Ransomware chain: ransomware + network (exfil before encrypt)
    { proc, anomalies, ids in
      guard ids.contains("ransomware"),
            ids.contains("network_anomaly") || ids.contains("cloud_c2") || ids.contains("dns_tunnel") else { return nil }
      return Correlation(id: UUID(), name: "Ransomware + Exfiltration",
        description: "\(proc): encryption + network exfiltration (double extortion)",
        scannerIds: Array(ids), anomalies: anomalies, severity: .critical,
        mitreChain: "T1486 → T1567")
    },
    // TCC abuse + credential access = surveillance
    { proc, anomalies, ids in
      guard ids.contains("tcc"),
            ids.contains("credential_access") || ids.contains("screen_capture") || ids.contains("clipboard") else { return nil }
      return Correlation(id: UUID(), name: "Surveillance Chain",
        description: "\(proc): TCC abuse + data collection",
        scannerIds: Array(ids), anomalies: anomalies, severity: .high,
        mitreChain: "T1005 → T1113")
    },
  ]

  // MARK: - Helpers

  /// Group anomalies by PID. Falls back to processPath for scanners
  /// that report pid=0 (e.g. offline/static analysis scanners).
  private static func groupByProcess(
    _ results: [ScannerResult]
  ) -> [String: [ProcessAnomaly]] {
    var map: [String: [ProcessAnomaly]] = [:]
    for r in results {
      for a in r.anomalies where !a.processName.isEmpty {
        let key = a.pid != 0 ? "\(a.pid)" : a.processPath
        map[key, default: []].append(a)
      }
    }
    return map
  }

  /// Build anomaly ID → scanner ID map in O(total anomalies) once,
  /// replacing O(anomalies × scanners × anomaliesPerScanner) per-lookup scan.
  private static func buildReverseMap(_ results: [ScannerResult]) -> [UUID: String] {
    var map: [UUID: String] = [:]
    for r in results {
      for a in r.anomalies { map[a.id] = r.id }
    }
    return map
  }
}
