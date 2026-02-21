import Foundation

/// Every probe answers 5 questions. No exceptions.
public struct ProbeMetadata: Sendable, Codable {
    /// What lie does this probe detect?
    public let whatLie: String
    /// What independent ground truth source(s) does it use?
    public let groundTruth: String
    /// What would an adversary need to do to defeat this probe?
    public let adversaryCost: String
    /// What does the user see when a contradiction is found?
    public let positiveDetection: String
    /// Expected false positive rate in normal operation
    public let falsePositiveRate: String
}

/// A probe that detects system lies by comparing independent sources.
/// Contradiction engines don't trust the OS — they TEST it.
public protocol ContradictionProbe: Sendable {
    /// Stable identifier: "dyld-cache", "sip-status", etc.
    var id: String { get }
    /// Human-readable name
    var name: String { get }
    /// The 5-question metadata — documentation IS the interface
    var metadata: ProbeMetadata { get }
    /// Run the probe. Returns structured comparison results.
    func run() async -> ProbeResult
}
