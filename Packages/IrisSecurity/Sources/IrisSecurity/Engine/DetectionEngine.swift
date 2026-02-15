import Foundation
import os.log

/// Core detection engine. Evaluates single-event rules and multi-event
/// correlation rules against incoming SecurityEvents.
public actor DetectionEngine {
    public static let shared = DetectionEngine()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "Detection")
    private let correlationState = CorrelationStateManager()

    private var simpleRules: [DetectionRule] = []
    private var correlationRules: [CorrelationRule] = []
    private var eventsProcessed: UInt64 = 0
    private var alertsProduced: UInt64 = 0

    /// Register detection rules. Call once at startup.
    public func loadRules(
        simple: [DetectionRule],
        correlation: [CorrelationRule]
    ) {
        self.simpleRules = simple
        self.correlationRules = correlation
        logger.info("[DET] Loaded \(simple.count) rules + \(correlation.count) correlation rules")
    }

    /// Process a single event through all rules.
    /// Produces alerts for any matches and stores them.
    public func process(_ event: SecurityEvent) async {
        eventsProcessed += 1

        // Evaluate simple (single-event) rules
        for rule in simpleRules {
            guard rule.matches(event) else { continue }
            let alert = SecurityAlert(
                ruleId: rule.id, name: rule.name,
                severity: rule.severity,
                mitreId: rule.mitreId, mitreName: rule.mitreName,
                processName: event.processName,
                processPath: event.processPath,
                description: formatDescription(rule: rule, event: event),
                events: [event]
            )
            await AlertStore.shared.add(alert)
            alertsProduced += 1
        }

        // Advance correlation rules
        for rule in correlationRules {
            if let completed = await correlationState.advance(rule: rule, event: event) {
                let alert = SecurityAlert(
                    ruleId: rule.id, name: rule.name,
                    severity: rule.severity,
                    mitreId: rule.mitreId, mitreName: rule.mitreName,
                    processName: event.processName,
                    processPath: event.processPath,
                    description: "Correlated \(completed.matchedStages) stages",
                    events: completed.events
                )
                await AlertStore.shared.add(alert)
                alertsProduced += 1
            }
        }

        // Periodic cleanup
        if eventsProcessed % 10000 == 0 {
            await correlationState.purgeExpired()
            logger.info("[DET] Stats: events=\(self.eventsProcessed) alerts=\(self.alertsProduced)")
        }
    }

    /// Process a batch of events
    public func processBatch(_ events: [SecurityEvent]) async {
        for event in events {
            await process(event)
        }
    }

    public func stats() -> (events: UInt64, alerts: UInt64, rules: Int, correlations: Int) {
        (eventsProcessed, alertsProduced, simpleRules.count, correlationRules.count)
    }

    private func formatDescription(rule: DetectionRule, event: SecurityEvent) -> String {
        let target = event.fields["target_path"] ?? event.fields["detail"] ?? ""
        return target.isEmpty ? "\(rule.mitreName)" : "\(rule.mitreName): \(target)"
    }
}
