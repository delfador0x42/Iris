import Foundation

/// A condition that must be satisfied for a rule to match.
/// Data-only — ThreatRuleLoader pattern-matches on these to build ThreatConditions.
public enum RuleCondition: Sendable {
    case fieldEquals(String, String)
    case fieldContains(String, String)
    case fieldMatchesRegex(String, String)
    case fieldHasPrefix(String, String)
    case processNotAppleSigned
    case processNameIn([String])
    case processNameNotIn([String])
    case parentNameIn([String])
    case processPathHasPrefix(String)
}

/// A single-event detection rule definition.
/// Data-only — ThreatRuleLoader converts these into ThreatRules.
public struct DetectionRule: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let eventType: String
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
}
