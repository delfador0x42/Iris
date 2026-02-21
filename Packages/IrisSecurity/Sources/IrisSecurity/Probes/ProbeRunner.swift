import Foundation
import os.log

/// Orchestrates contradiction probes — runs all in parallel, writes JSON output.
@Observable
public final class ProbeRunner: @unchecked Sendable {
    public static let shared = ProbeRunner()

    public private(set) var results: [ProbeResult] = []
    public private(set) var isRunning = false
    public private(set) var lastRunDate: Date?
    /// Temporal deltas from last run (what changed)
    public private(set) var deltas: [ProbeDelta] = []

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ProbeRunner")

    /// All registered contradiction probes
    private var probes: [any ContradictionProbe] = []

    private init() {}

    /// Register probes. Called once at app startup.
    public func register(_ probes: [any ContradictionProbe]) {
        self.probes = probes
    }

    /// Run all probes in parallel. Writes results to ~/.iris/probes/.
    @discardableResult
    public func runAll() async -> [ProbeResult] {
        isRunning = true
        defer { isRunning = false }
        let start = Date()

        // Load previous results for temporal diff
        let previousResults = ProbeStore.readLatest()

        logger.info("Starting \(self.probes.count) contradiction probes")

        let probeResults = await withTaskGroup(of: ProbeResult.self) { group in
            for probe in probes {
                group.addTask {
                    await probe.run()
                }
            }
            var collected: [ProbeResult] = []
            collected.reserveCapacity(probes.count)
            for await result in group {
                collected.append(result)
                ProbeStore.write(result)
            }
            return collected
        }

        // Temporal diff: detect state changes between runs
        let newDeltas = ProbeDiff.diff(current: probeResults, previous: previousResults)
        if !newDeltas.isEmpty {
            ProbeDiff.writeDiff(newDeltas)
            for delta in newDeltas {
                logger.warning("PROBE STATE CHANGE: \(delta.probeName) — \(delta.change)")
            }
        }

        ProbeStore.writeSummary(probeResults)
        results = probeResults
        deltas = newDeltas
        lastRunDate = Date()

        let contradictions = probeResults.filter { $0.verdict == .contradiction }.count
        let duration = Date().timeIntervalSince(start)
        logger.info("Probes complete: \(probeResults.count) run, \(contradictions) contradictions, \(newDeltas.count) state changes, \(String(format: "%.1f", duration))s")

        return probeResults
    }

    /// Run a single probe by ID
    public func runOne(id: String) async -> ProbeResult? {
        guard let probe = probes.first(where: { $0.id == id }) else {
            logger.warning("No probe with id '\(id)'")
            return nil
        }
        let result = await probe.run()
        ProbeStore.write(result)
        // Update in results array
        if let idx = results.firstIndex(where: { $0.probeId == id }) {
            results[idx] = result
        } else {
            results.append(result)
        }
        return result
    }

    /// Convert all results to ProcessAnomaly for existing scan pipeline
    public func toAnomalies() -> [ProcessAnomaly] {
        results.flatMap { $0.toAnomalies() }
    }

    /// List registered probe IDs
    public var probeIds: [String] {
        probes.map(\.id)
    }
}
