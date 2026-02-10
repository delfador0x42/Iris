import Foundation

/// Category of evidence that raised concern
public enum EvidenceCategory: String, Sendable, Codable {
    case signing     // Code signature problems
    case content     // What's inside (dangerous commands, encoded strings)
    case location    // Where it lives (/tmp, /Users, hidden paths)
    case behavior    // What it does (network, keychain, injection)
    case context     // Contextual (deprecated API, non-standard mechanism)
}

/// A piece of evidence that raises concern about a finding.
/// Weights are 0.0 to 1.0. Evidence only accumulates upward —
/// nothing gets a pass, nothing reduces suspicion.
public struct Evidence: Sendable, Codable, Equatable {
    public let factor: String
    public let weight: Double
    public let category: EvidenceCategory

    public init(factor: String, weight: Double, category: EvidenceCategory) {
        self.factor = factor
        self.weight = min(max(weight, 0.0), 1.0)
        self.category = category
    }
}

/// Compute suspicion score from accumulated evidence.
/// Score = sum of weights, clamped to [0, 1].
public func computeSuspicionScore(from evidence: [Evidence]) -> Double {
    min(evidence.reduce(0.0) { $0 + $1.weight }, 1.0)
}

/// Derive severity from a suspicion score.
public func severityFromScore(_ score: Double) -> AnomalySeverity {
    switch score {
    case 0.8...: return .critical
    case 0.6..<0.8: return .high
    case 0.3..<0.6: return .medium
    default: return .low
    }
}
