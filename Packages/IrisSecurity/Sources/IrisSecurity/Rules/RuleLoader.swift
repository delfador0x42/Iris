import Foundation

/// Aggregates all detection rules from all modules and loads them
/// into the DetectionEngine at startup.
public enum RuleLoader {

    /// All simple (single-event) detection rules
    public static func allSimpleRules() -> [DetectionRule] {
        var rules: [DetectionRule] = []
        rules.append(contentsOf: CredentialTheftRules.rules())
        rules.append(contentsOf: PersistenceRules.rules())
        rules.append(contentsOf: C2Rules.rules())
        rules.append(contentsOf: EvasionRules.rules())
        rules.append(contentsOf: InjectionRules.rules())
        rules.append(contentsOf: ExfiltrationRules.rules())
        rules.append(contentsOf: APTRules.rules())
        rules.append(contentsOf: NationStateRules.rules())
        return rules
    }

    /// All multi-event correlation rules
    public static func allCorrelationRules() -> [CorrelationRule] {
        CorrelationRuleDefinitions.rules()
    }

    /// Initialize the DetectionEngine with all rules
    public static func loadAll() async {
        let simple = allSimpleRules()
        let correlation = allCorrelationRules()
        await DetectionEngine.shared.loadRules(simple: simple, correlation: correlation)
    }
}
