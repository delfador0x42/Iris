import Combine
import SwiftUI

/// Observable scan session for live UI updates.
/// Wraps SecurityAssessor.scanThreats() with progress tracking.
@MainActor
public final class ScanSession: ObservableObject {
  @Published public var scannerResults: [ScannerResult] = []
  @Published public var isScanning = false
  @Published public var completed = 0
  @Published public var total = 0
  @Published public var latestScanner = ""
  @Published public var scanResult: ThreatScanResult?
  @Published public var diff: FindingsDiff?
  @Published public var correlations: [CorrelationEngine.Correlation] = []
  @Published public var allowlistSuppressedCount = 0
  @Published public var vtResults: [String: VTVerdict] = [:]
  @Published public var vtChecking = false

  public init() {}

  /// Run a full scan with live progress updates.
  public func runScan() async {
    isScanning = true
    completed = 0
    total = ScannerEntry.all.count
    scannerResults = []
    latestScanner = ""

    let previousResult = await SecurityAssessor.shared.cachedResult

    let result = await SecurityAssessor.shared.scanThreats {
      [weak self] (progress: ScannerProgress) in
      Task { @MainActor in
        guard let self else { return }
        self.completed = progress.completed
        self.latestScanner = progress.latestResult.name
        self.scannerResults.append(progress.latestResult)
      }
    }

    scanResult = result
    correlations = result.correlations
    allowlistSuppressedCount = result.allowlistSuppressed
    if let previous = previousResult {
      diff = FindingsDiff.compute(current: result, previous: previous)
    }
    isScanning = false

    // Fire-and-forget VT hash checks (display-only, no trust signal)
    Task { await checkVirusTotal(result.anomalies) }

    // Auto-carve memory for suspicious processes (hidden, fileless, injected)
    Task { await carveMemoryForSuspicious(result.anomalies) }
  }

  /// Load cached result without running a new scan.
  public func loadCached() async {
    if let cached = await SecurityAssessor.shared.cachedResult {
      scanResult = cached
      scannerResults = cached.scannerResults
      completed = cached.scannerCount
      total = cached.scannerCount
    }
  }

  /// Check if a scanner has completed.
  public func isComplete(_ id: String) -> Bool {
    scannerResults.contains { $0.id == id }
  }

  /// Get result for a specific scanner.
  public func result(for id: String) -> ScannerResult? {
    scannerResults.first { $0.id == id }
  }

  /// Check findings against VirusTotal (display-only, not a trust signal).
  private func checkVirusTotal(_ anomalies: [ProcessAnomaly]) async {
    let vt = VirusTotalService.shared
    guard await vt.loadKey() else { return }
    vtChecking = true
    let results = await vt.checkFindings(anomalies)
    vtResults = results
    vtChecking = false
  }

  /// Get VT verdict for a file path, if available.
  public func vtVerdict(for path: String) -> VTVerdict? {
    vtResults[path]
  }

  /// Carve executable memory from suspicious processes for offline analysis.
  /// Targets: hidden processes, deleted binaries, injection findings.
  private func carveMemoryForSuspicious(_ anomalies: [ProcessAnomaly]) async {
    let carveTargets = Set(["Hidden Process", "Deleted Binary Still Running",
                            "Hidden Process (kill brute-force)",
                            "Hidden Process (Mach task walk)"])
    let pids = Set(anomalies.filter { carveTargets.contains($0.technique) && $0.pid > 0 }.map(\.pid))
    guard !pids.isEmpty else { return }
    for pid in pids {
      if let carved = MemoryCarver.carve(pid: pid) {
        await MainActor.run {
          vtResults["carved:\(pid)"] = nil // placeholder for future VT check
        }
        // Check carved hash against VT
        if await VirusTotalService.shared.loadKey() {
          let verdict = await VirusTotalService.shared.checkHash(carved.sha256)
          if let v = verdict {
            await MainActor.run { vtResults["carved:\(pid)"] = v }
          }
        }
      }
    }
    MemoryCarver.cleanup()
  }

  /// Current results (complete or in-progress). Enables export during scan.
  public var currentResult: ThreatScanResult {
    scanResult ?? ThreatScanResult(
      anomalies: scannerResults.flatMap(\.anomalies),
      supplyChainFindings: [], fsChanges: [],
      scannerResults: scannerResults,
      correlations: correlations, allowlistSuppressed: allowlistSuppressedCount,
      scanDuration: 0, scannerCount: scannerResults.count,
      timestamp: Date()
    )
  }
}
