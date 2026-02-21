import Foundation

/// What the probe concluded.
public enum ProbeVerdict: String, Sendable, Codable {
    /// All sources agree — system is consistent
    case consistent
    /// Sources disagree — possible tampering
    case contradiction
    /// Couldn't reach all sources — partial check
    case degraded
    /// Probe failed entirely
    case error
}

/// One comparison between two independent sources.
public struct SourceComparison: Sendable, Codable, Identifiable {
    public let id: UUID
    /// Human-readable label: "disk UUID vs runtime API UUID"
    public let label: String
    /// What source A reported
    public let sourceA: SourceValue
    /// What source B reported
    public let sourceB: SourceValue
    /// Did they agree?
    public let matches: Bool

    public init(label: String, sourceA: SourceValue, sourceB: SourceValue, matches: Bool) {
        self.id = UUID()
        self.label = label
        self.sourceA = sourceA
        self.sourceB = sourceB
        self.matches = matches
    }
}

/// A value from one independent source.
public struct SourceValue: Sendable, Codable {
    /// Source name: "disk", "runtime API", "mapped memory"
    public let source: String
    /// The actual value as string
    public let value: String

    public init(_ source: String, _ value: String) {
        self.source = source
        self.value = value
    }
}

/// Complete probe result with structured comparison data.
public struct ProbeResult: Sendable, Codable, Identifiable {
    public let id: UUID
    public let probeId: String
    public let probeName: String
    public let verdict: ProbeVerdict
    public let comparisons: [SourceComparison]
    public let message: String
    public let timestamp: Date
    public let durationMs: Int

    public init(
        probeId: String, probeName: String, verdict: ProbeVerdict,
        comparisons: [SourceComparison], message: String, durationMs: Int
    ) {
        self.id = UUID()
        self.probeId = probeId
        self.probeName = probeName
        self.verdict = verdict
        self.comparisons = comparisons
        self.message = message
        self.timestamp = Date()
        self.durationMs = durationMs
    }

    /// Backward compatibility — convert to ProcessAnomaly array for existing scan pipeline
    public func toAnomalies() -> [ProcessAnomaly] {
        guard verdict == .contradiction else { return [] }
        return comparisons.filter { !$0.matches }.map { cmp in
            ProcessAnomaly.filesystem(
                name: probeName, path: "contradiction:\(probeId)",
                technique: "\(probeName) Contradiction",
                description: "\(cmp.label): \(cmp.sourceA.source)=\(cmp.sourceA.value) vs \(cmp.sourceB.source)=\(cmp.sourceB.value)",
                severity: .critical, mitreID: "T1014",
                scannerId: probeId,
                enumMethod: "\(cmp.sourceA.source) vs \(cmp.sourceB.source)",
                evidence: [
                    "source_a: \(cmp.sourceA.source) = \(cmp.sourceA.value)",
                    "source_b: \(cmp.sourceB.source) = \(cmp.sourceB.value)",
                    "matches: \(cmp.matches)",
                ])
        }
    }
}
