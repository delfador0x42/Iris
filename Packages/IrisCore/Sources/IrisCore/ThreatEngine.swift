import Foundation
import os.log

/// Unified detection pipeline. Replaces DetectionEngine + CorrelationEngine + FusionEngine.
/// Rules indexed by Kind discriminator → O(1) dispatch instead of O(n×m).
/// Streaming correlation with bounded state. Emits alerts as Events to EventStream.
public actor ThreatEngine {
    public static let shared = ThreatEngine()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ThreatEngine")

    // Rules indexed by Kind discriminator for O(1) dispatch
    private var ruleIndex: [String: [ThreatRule]] = [:]
    private var correlationRules: [StreamCorrelationRule] = []

    // Streaming correlation state: [keyValue: [Progress]]
    private var correlationState: [String: [CorrelationProgress]] = [:]
    private let maxCorrelationKeys = 2000

    // Stats
    private var eventsProcessed: UInt64 = 0
    private var alertsProduced: UInt64 = 0

    // MARK: - Setup

    /// Load rules and build the dispatch index. Call once at startup.
    public func loadRules(
        simple: [ThreatRule],
        correlation: [StreamCorrelationRule] = []
    ) {
        ruleIndex.removeAll()
        for rule in simple {
            for kind in rule.kinds {
                ruleIndex[kind, default: []].append(rule)
            }
        }
        correlationRules = correlation
        logger.info("[THREAT] Loaded \(simple.count) rules (\(self.ruleIndex.count) kind buckets) + \(correlation.count) correlation")
    }

    // MARK: - Process

    /// Process one Event. O(1) kind dispatch + evaluate matching rules.
    public func process(_ event: Event) async {
        eventsProcessed += 1

        // O(1) dispatch: only evaluate rules indexed for this kind
        let disc = event.kind.discriminator
        if let rules = ruleIndex[disc] {
            for rule in rules {
                guard rule.matches(event) else { continue }
                let alert = Event(
                    id: EventIDGen.shared.next(),
                    source: .engine,
                    severity: rule.severity,
                    process: event.process,
                    kind: .alert(
                        rule: rule.id, name: rule.name,
                        mitre: rule.mitre, detail: rule.detail(event),
                        chain: [event.id]))
                await EventStream.shared.emit(alert)
                alertsProduced += 1
            }
        }

        // Advance streaming correlation
        for rule in correlationRules {
            if let completed = advanceCorrelation(rule: rule, event: event) {
                let ids = completed.eventIds
                let alert = Event(
                    id: EventIDGen.shared.next(),
                    source: .engine,
                    severity: rule.severity,
                    process: event.process,
                    kind: .alert(
                        rule: rule.id, name: rule.name,
                        mitre: rule.mitre,
                        detail: "Correlated \(completed.matchedStages) stages",
                        chain: ids))
                await EventStream.shared.emit(alert)
                alertsProduced += 1
            }
        }

        // Periodic cleanup
        if eventsProcessed % 10000 == 0 {
            purgeExpired()
            logger.info("[THREAT] events=\(self.eventsProcessed) alerts=\(self.alertsProduced)")
        }
    }

    /// Process a batch.
    public func processBatch(_ events: [Event]) async {
        for event in events { await process(event) }
    }

    // MARK: - Stats

    public func stats() -> (events: UInt64, alerts: UInt64, ruleBuckets: Int, correlations: Int) {
        (eventsProcessed, alertsProduced, ruleIndex.count, correlationRules.count)
    }

    // MARK: - Streaming Correlation

    private struct CorrelationProgress {
        let ruleId: String
        let matchedStages: Int
        let startTime: UInt64  // nanoseconds
        let eventIds: [UInt64]
    }

    private func advanceCorrelation(rule: StreamCorrelationRule, event: Event) -> CorrelationProgress? {
        let kv = rule.keyExtractor(event)
        guard !kv.isEmpty else { return nil }
        let now = event.ts

        // Clean expired
        let windowNs = UInt64(rule.window * 1_000_000_000)
        correlationState[kv]?.removeAll { p in
            p.ruleId == rule.id && (now > p.startTime + windowNs)
        }

        let existing = correlationState[kv]?.first { $0.ruleId == rule.id }
        let nextIdx = existing?.matchedStages ?? 0
        guard nextIdx < rule.stages.count else { return nil }

        let stage = rule.stages[nextIdx]
        guard stage.matches(event) else { return nil }

        let progress = CorrelationProgress(
            ruleId: rule.id,
            matchedStages: nextIdx + 1,
            startTime: existing?.startTime ?? now,
            eventIds: (existing?.eventIds ?? []) + [event.id])

        // Remove old progress for this rule
        correlationState[kv]?.removeAll { $0.ruleId == rule.id }

        // All stages matched?
        if progress.matchedStages >= rule.stages.count {
            return progress
        }

        // Store updated progress (bounded)
        if correlationState[kv] == nil {
            if correlationState.count >= maxCorrelationKeys {
                // Evict oldest key
                if let oldest = correlationState.min(by: {
                    ($0.value.first?.startTime ?? .max) < ($1.value.first?.startTime ?? .max)
                }) {
                    correlationState.removeValue(forKey: oldest.key)
                }
            }
            correlationState[kv] = []
        }
        correlationState[kv]?.append(progress)
        return nil
    }

    private func purgeExpired() {
        let now = Clock.now()
        let maxAge: UInt64 = 300_000_000_000 // 5 minutes in ns
        for key in correlationState.keys {
            correlationState[key]?.removeAll { now > $0.startTime + maxAge }
            if correlationState[key]?.isEmpty == true { correlationState[key] = nil }
        }
    }
}
