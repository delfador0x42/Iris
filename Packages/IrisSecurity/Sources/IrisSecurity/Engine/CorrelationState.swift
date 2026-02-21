import Foundation

/// Tracks progress of an in-flight correlation
struct CorrelationProgress: Sendable {
    let ruleId: String
    let matchedStages: Int          // how many stages matched so far
    let firstEventTime: Date
    let events: [SecurityEvent]     // contributing events
}

/// Manages in-flight correlation state. Keyed by correlation key value.
/// Evicts expired entries that exceed the rule's time window.
actor CorrelationStateManager {
    /// Active correlations: [correlationKeyValue: [CorrelationProgress]]
    private var active: [String: [CorrelationProgress]] = [:]

    /// Maximum unique keys to prevent memory DoS from many concurrent processes
    private let maxKeys = 2000

    /// Extract the correlation key value from an event
    func keyValue(for event: SecurityEvent, key: CorrelationKey) -> String {
        switch key {
        case .pid: return "\(event.pid)"
        case .processPath: return event.processPath
        case .signingId: return event.signingId ?? event.processPath
        }
    }

    /// Try to advance correlation for a given rule. Returns completed progress if all stages matched.
    func advance(
        rule: CorrelationRule,
        event: SecurityEvent
    ) -> CorrelationProgress? {
        let kv = keyValue(for: event, key: rule.correlationKey)
        let now = event.timestamp

        // Clean expired entries for this key
        active[kv]?.removeAll { progress in
            progress.ruleId == rule.id &&
            now.timeIntervalSince(progress.firstEventTime) > rule.timeWindow
        }

        // Find existing progress for this rule
        let existing = active[kv]?.first { $0.ruleId == rule.id }

        let nextStageIndex = existing?.matchedStages ?? 0
        guard nextStageIndex < rule.stages.count else { return nil }

        let nextStage = rule.stages[nextStageIndex]
        guard nextStage.matches(event) else { return nil }

        let newProgress = CorrelationProgress(
            ruleId: rule.id,
            matchedStages: nextStageIndex + 1,
            firstEventTime: existing?.firstEventTime ?? now,
            events: (existing?.events ?? []) + [event]
        )

        // Remove old progress
        active[kv]?.removeAll { $0.ruleId == rule.id }

        // Check if all stages completed
        if newProgress.matchedStages >= rule.stages.count {
            return newProgress
        }

        // Store updated progress (with cap to prevent unbounded growth)
        if active[kv] == nil {
            if active.count >= maxKeys {
                // Evict oldest key by earliest firstEventTime
                if let oldest = active.min(by: { ($0.value.first?.firstEventTime ?? .distantFuture) < ($1.value.first?.firstEventTime ?? .distantFuture) }) {
                    active.removeValue(forKey: oldest.key)
                }
            }
            active[kv] = []
        }
        active[kv]?.append(newProgress)
        return nil
    }

    /// Purge expired entries across all keys
    func purgeExpired(olderThan maxAge: TimeInterval = 300) {
        let cutoff = Date().addingTimeInterval(-maxAge)
        for key in active.keys {
            active[key]?.removeAll { $0.firstEventTime < cutoff }
            if active[key]?.isEmpty == true { active[key] = nil }
        }
    }
}
