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
}
