import Foundation
import os.log

/// Runs all security checks and computes an overall security grade.
/// Entry point for the security assessment engine.
/// Scanner orchestration lives in SecurityAssessor+Scanners.swift.
public actor SecurityAssessor {
  public static let shared = SecurityAssessor()

  private let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityAssessor")

  /// Cached last scan result for quick access.
  /// Internal so SecurityAssessor+Scanners.swift extension can write to it.
  var lastResult: ThreatScanResult?

  /// Most recent scan result (nil if never scanned)
  public var cachedResult: ThreatScanResult? { lastResult }

  /// Run all security checks and return results with grade
  public func assess() async -> (checks: [SecurityCheck], grade: SecurityGrade) {
    logger.info("Starting security assessment")

    var allChecks: [SecurityCheck] = []

    // System-level checks (SIP, FileVault, Gatekeeper, Firewall, etc.)
    let systemChecks = await SystemSecurityChecks.runAll()
    allChecks.append(contentsOf: systemChecks)

    // Run all threat scanners via unified orchestration
    let result = await scanThreats()
    allChecks.append(contentsOf: convertToChecks(result))

    allChecks.sort { lhs, rhs in
      if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
      return lhs.category.rawValue < rhs.category.rawValue
    }

    let grade = SecurityGrade.compute(from: allChecks)
    logger.info(
      "Assessment: \(grade.letter) (\(grade.score)/100), \(allChecks.count) checks, \(String(format: "%.1f", result.scanDuration))s"
    )
    return (allChecks, grade)
  }

  /// Convert ThreatScanResult into SecurityChecks for grading
  private func convertToChecks(_ result: ThreatScanResult) -> [SecurityCheck] {
    var checks: [SecurityCheck] = []

    // Anomalies → SecurityCheck
    checks.append(contentsOf: result.anomalies.map { anomaly in
      SecurityCheck(
        category: .threats, name: anomaly.technique,
        description: "\(anomaly.processName): \(anomaly.description)",
        status: .fail, severity: CheckSeverity(anomaly.severity))
    })

    // Supply chain → SecurityCheck
    checks.append(contentsOf: result.supplyChainFindings.map { finding in
      SecurityCheck(
        category: .threats, name: "Supply Chain: \(finding.finding)",
        description: "\(finding.packageName): \(finding.details)",
        status: .fail, severity: CheckSeverity(finding.severity))
    })

    // FS changes → SecurityCheck
    checks.append(contentsOf: result.fsChanges.map { change in
      SecurityCheck(
        category: .threats, name: change.changeType.rawValue,
        description: "\(change.path): \(change.details)",
        status: .fail, severity: CheckSeverity(change.severity))
    })

    return checks
  }
}

// MARK: - Severity conversion

extension CheckSeverity {
  init(_ anomaly: AnomalySeverity) {
    switch anomaly {
    case .critical: self = .critical
    case .high: self = .high
    case .medium: self = .medium
    case .low: self = .low
    }
  }
}
