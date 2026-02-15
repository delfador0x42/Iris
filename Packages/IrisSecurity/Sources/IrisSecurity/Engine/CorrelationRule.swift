import Foundation

/// How to correlate events across stages (same PID, same process path, etc.)
public enum CorrelationKey: Sendable {
    case pid
    case processPath
    case signingId
}

/// One stage in a multi-event correlation rule
public struct RuleStage: Sendable {
    public let eventType: String
    public let conditions: [RuleCondition]

    public init(eventType: String, conditions: [RuleCondition] = []) {
        self.eventType = eventType
        self.conditions = conditions
    }

    func matches(_ event: SecurityEvent) -> Bool {
        guard event.eventType == eventType else { return false }
        return conditions.allSatisfy { $0.matches(event) }
    }
}

/// A multi-event temporal correlation rule.
/// All stages must match in order within the time window.
public struct CorrelationRule: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let stages: [RuleStage]
    public let timeWindow: TimeInterval
    public let correlationKey: CorrelationKey
    public let severity: AnomalySeverity
    public let mitreId: String
    public let mitreName: String

    public init(
        id: String, name: String,
        stages: [RuleStage],
        timeWindow: TimeInterval,
        correlationKey: CorrelationKey,
        severity: AnomalySeverity,
        mitreId: String, mitreName: String
    ) {
        self.id = id
        self.name = name
        self.stages = stages
        self.timeWindow = timeWindow
        self.correlationKey = correlationKey
        self.severity = severity
        self.mitreId = mitreId
        self.mitreName = mitreName
    }
}
