import Foundation
import os.log

/// Runs all contradiction probes on a periodic schedule and feeds results
/// into AlertStore (notifications) and EventStream (single JSONL log).
///
/// Fast probes (process census, architecture, code signing) run every 60s.
/// Slow probes (trust cache, binary integrity, IOKit) run every 300s.
public actor ContradictionEngine {
    public static let shared = ContradictionEngine()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "ContradictionEngine")

    private var isRunning = false
    private var fastTask: Task<Void, Never>?
    private var slowTask: Task<Void, Never>?
    private var lastResults: [ProbeResult] = []

    /// Fast-cycle probes (lightweight, ~60s interval)
    private let fastProbeIds: Set<String> = [
        "process-census", "architecture", "codesign-contradiction",
        "mac-policy", "kernel-boot",
    ]

    /// Start periodic probe execution
    public func start() {
        guard !isRunning else { return }
        isRunning = true

        // Run all probes once immediately
        fastTask = Task { await fastLoop() }
        slowTask = Task { await slowLoop() }
        logger.info("[CONTRADICTION] Engine started")
    }

    /// Stop periodic execution
    public func stop() {
        isRunning = false
        fastTask?.cancel()
        slowTask?.cancel()
        fastTask = nil
        slowTask = nil
        logger.info("[CONTRADICTION] Engine stopped")
    }

    /// Current results
    public func results() -> [ProbeResult] { lastResults }

    // MARK: - Loops

    private func fastLoop() async {
        // Initial delay to let the system settle after boot
        try? await Task.sleep(nanoseconds: 10_000_000_000)

        while isRunning && !Task.isCancelled {
            let runner = ProbeRunner.shared
            let allResults = await runner.runAll()

            // Filter to fast probes
            let results = allResults.filter { fastProbeIds.contains($0.probeId) }
            await processResults(results)

            try? await Task.sleep(nanoseconds: 60_000_000_000)
        }
    }

    private func slowLoop() async {
        // Initial delay — slow probes start after 30s
        try? await Task.sleep(nanoseconds: 30_000_000_000)

        while isRunning && !Task.isCancelled {
            let runner = ProbeRunner.shared
            let allResults = await runner.runAll()

            // Filter to slow probes (everything NOT in fast set)
            let results = allResults.filter { !fastProbeIds.contains($0.probeId) }
            await processResults(results)

            try? await Task.sleep(nanoseconds: 300_000_000_000)
        }
    }

    private func processResults(_ results: [ProbeResult]) async {
        lastResults = results

        // Emit every result to EventStream (the single data path)
        for result in results {
            let verdict: Verdict = switch result.verdict {
            case .consistent: .clean
            case .contradiction: .contradiction
            case .degraded, .error: .error
            }
            let mismatches = result.comparisons.filter { !$0.matches }.map {
                Contradiction(
                    label: $0.label,
                    sourceA: $0.sourceA.source, valueA: $0.sourceA.value,
                    sourceB: $0.sourceB.source, valueB: $0.sourceB.value)
            }
            await EventStream.shared.emit(
                EventBridge.fromProbe(probeId: result.probeId, verdict: verdict, contradictions: mismatches))
        }

        // Generate alerts for contradictions
        let contradictions = results.filter { $0.verdict == .contradiction }
        for result in contradictions {
            let alert = SecurityAlert(
                ruleId: "probe-\(result.probeId)",
                name: "Probe Contradiction: \(result.probeName)",
                severity: .critical,
                mitreId: "T1014",
                mitreName: "Rootkit",
                processName: "iris-probe",
                processPath: "contradiction:\(result.probeId)",
                description: result.message)
            await AlertStore.shared.add(alert)

            logger.critical("[CONTRADICTION] \(result.probeName): \(result.message)")
        }

        if !contradictions.isEmpty {
            logger.warning("[CONTRADICTION] \(contradictions.count) probe(s) found contradictions")
        }
    }
}
