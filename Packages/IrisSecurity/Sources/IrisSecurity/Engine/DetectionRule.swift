import Foundation

/// A condition that must be satisfied for a rule to match
public enum RuleCondition: Sendable {
    case fieldEquals(String, String)
    case fieldContains(String, String)
    case fieldMatchesRegex(String, String)
    case fieldHasPrefix(String, String)
    case processNotAppleSigned
    case processNameNotIn([String])
    case processPathHasPrefix(String)

    /// Evaluate this condition against a SecurityEvent
    func matches(_ event: SecurityEvent) -> Bool {
        switch self {
        case .fieldEquals(let key, let value):
            return event.fields[key] == value
        case .fieldContains(let key, let substring):
            return event.fields[key]?.contains(substring) == true
        case .fieldMatchesRegex(let key, let pattern):
            guard let val = event.fields[key],
                  let regex = try? NSRegularExpression(pattern: pattern) else { return false }
            return regex.firstMatch(in: val, range: NSRange(val.startIndex..., in: val)) != nil
        case .fieldHasPrefix(let key, let prefix):
            return event.fields[key]?.hasPrefix(prefix) == true
        case .processNotAppleSigned:
            return !event.isAppleSigned
        case .processNameNotIn(let names):
            return !names.contains(event.processName)
        case .processPathHasPrefix(let prefix):
            return event.processPath.hasPrefix(prefix)
        }
    }
}

/// A single-event detection rule. Matches one event at a time.
public struct DetectionRule: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let eventType: String         // match SecurityEvent.eventType
    public let conditions: [RuleCondition]
    public let severity: AnomalySeverity
    public let mitreId: String
    public let mitreName: String

    public init(
        id: String, name: String, eventType: String,
        conditions: [RuleCondition],
        severity: AnomalySeverity,
        mitreId: String, mitreName: String
    ) {
        self.id = id
        self.name = name
        self.eventType = eventType
        self.conditions = conditions
        self.severity = severity
        self.mitreId = mitreId
        self.mitreName = mitreName
    }

    /// Check if this rule matches the given event
    func matches(_ event: SecurityEvent) -> Bool {
        guard event.eventType == eventType else { return false }
        return conditions.allSatisfy { $0.matches(event) }
    }
}
