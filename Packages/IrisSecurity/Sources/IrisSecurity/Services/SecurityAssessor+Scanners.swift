import Foundation

/// Full threat scan result with categorized findings and per-scanner timing.
public struct ThreatScanResult: Sendable {
  public let anomalies: [ProcessAnomaly]
  public let supplyChainFindings: [SupplyChainFinding]
  public let fsChanges: [FileSystemChange]
  public let scannerResults: [ScannerResult]
  public let correlations: [CorrelationEngine.Correlation]
  public let allowlistSuppressed: Int
  public let scanDuration: TimeInterval
  public let scannerCount: Int
  public let timestamp: Date

  public var totalFindings: Int {
    anomalies.count + supplyChainFindings.count + fsChanges.count
  }

  public var criticalCount: Int {
    anomalies.filter { $0.severity == .critical }.count
      + fsChanges.filter { $0.severity == .critical }.count
      + correlations.filter { $0.severity == .critical }.count
  }

  public var highCount: Int {
    anomalies.filter { $0.severity == .high }.count
      + supplyChainFindings.filter { $0.severity == .high }.count
      + fsChanges.filter { $0.severity == .high }.count
      + correlations.filter { $0.severity == .high }.count
  }
}

/// Progress update emitted after each scanner completes.
public struct ScannerProgress: Sendable {
  public let completed: Int
  public let total: Int
  public let latestResult: ScannerResult
}

// MARK: - Scanner Orchestration via Registry

extension SecurityAssessor {

  /// Run all scanners via registry with TaskGroup, tiered execution, and per-scanner timing.
  /// Replaces the 50-line async let block with a data-driven approach.
  /// - Parameter onProgress: Optional callback fired after each scanner completes.
  public func scanThreats(
    onProgress: (@Sendable (ScannerProgress) -> Void)? = nil
  ) async -> ThreatScanResult {
    let start = Date()
    let ctx = ScanContext(
      snapshot: ProcessSnapshot.capture(),
      connections: await MainActor.run { SecurityStore.shared.connections }
    )

    // Fire supply chain + filesystem baseline alongside registry scanners
    async let scFindings = SupplyChainAuditor.shared.auditAll()
    async let fsChanges = FileSystemBaseline.shared.diff()

    // Run registry scanners tier by tier (fast results arrive first)
    let allowlist = AllowlistStore.shared
    var allResults: [ScannerResult] = []
    var totalSuppressed = 0
    allResults.reserveCapacity(ScannerEntry.all.count)

    for tier in [ScannerTier.fast, .medium, .slow] {
      let entries = ScannerEntry.all.filter { $0.tier == tier }
      let tierResults = await withTaskGroup(of: (ScannerResult, Int).self) { group in
        for entry in entries {
          group.addTask {
            let t = Date()
            let rawAnomalies = await entry.run(ctx)
            let filtered = await allowlist.filter(rawAnomalies, scannerId: entry.id)
            let suppressed = rawAnomalies.count - filtered.count
            let result = ScannerResult(
              id: entry.id, name: entry.name, tier: entry.tier,
              anomalies: filtered, duration: Date().timeIntervalSince(t),
              timestamp: Date())
            return (result, suppressed)
          }
        }
        var results: [(ScannerResult, Int)] = []
        results.reserveCapacity(entries.count)
        for await pair in group {
          results.append(pair)
          onProgress?(ScannerProgress(
            completed: allResults.count + results.count,
            total: ScannerEntry.all.count,
            latestResult: pair.0))
        }
        return results
      }
      for (result, suppressed) in tierResults {
        allResults.append(result)
        totalSuppressed += suppressed
      }
    }

    // Cross-scanner correlation
    let correlations = CorrelationEngine.correlate(allResults)

    let result = ThreatScanResult(
      anomalies: allResults.flatMap(\.anomalies).sorted { $0.severity > $1.severity },
      supplyChainFindings: await scFindings,
      fsChanges: await fsChanges,
      scannerResults: allResults,
      correlations: correlations,
      allowlistSuppressed: totalSuppressed,
      scanDuration: Date().timeIntervalSince(start),
      scannerCount: allResults.count,
      timestamp: Date())

    lastResult = result
    return result
  }
}
