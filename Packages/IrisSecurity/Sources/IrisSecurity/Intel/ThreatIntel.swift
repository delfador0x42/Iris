import Foundation

/// Type of threat indicator
public enum IndicatorType: String, Sendable, Codable {
    case persistenceLabel    // LaunchAgent/Daemon label
    case c2Domain            // C2 server hostname
    case filePath            // Known malicious file path
    case processName         // Known malicious process name
    case signingId           // Known malicious signing identity
}

/// A threat intelligence indicator from known malware families
public struct ThreatIndicator: Sendable {
    public let type: IndicatorType
    public let value: String
    public let malwareFamily: String
    public let mitreId: String
    public let severity: AnomalySeverity

    public init(
        type: IndicatorType, value: String,
        malwareFamily: String, mitreId: String,
        severity: AnomalySeverity
    ) {
        self.type = type
        self.value = value
        self.malwareFamily = malwareFamily
        self.mitreId = mitreId
        self.severity = severity
    }
}

/// Central threat intelligence lookup.
/// Indicator arrays are built once (static let) to avoid per-call allocation.
public enum ThreatIntelStore {

    // Cached indicator arrays — built once at first access
    private static let persistenceIndicators = MalwarePersistence.indicators()
    private static let c2Indicators = MalwareC2.indicators()
    private static let pathIndicators = TargetedPaths.indicators()

    /// All indicators from all modules
    public static func allIndicators() -> [ThreatIndicator] {
        persistenceIndicators + c2Indicators + pathIndicators
    }

    /// Lookup a persistence label against known malware
    public static func checkPersistenceLabel(_ label: String) -> ThreatIndicator? {
        persistenceIndicators.first { label.contains($0.value) }
    }

    /// Lookup a hostname against known C2 infrastructure
    public static func checkHostname(_ hostname: String) -> ThreatIndicator? {
        c2Indicators.first { hostname.contains($0.value) }
    }
}
