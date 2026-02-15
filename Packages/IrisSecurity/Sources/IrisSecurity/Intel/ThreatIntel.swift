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

/// Central threat intelligence lookup
public enum ThreatIntelStore {

    /// All indicators from all modules
    public static func allIndicators() -> [ThreatIndicator] {
        var all: [ThreatIndicator] = []
        all.append(contentsOf: MalwarePersistence.indicators())
        all.append(contentsOf: MalwareC2.indicators())
        all.append(contentsOf: TargetedPaths.indicators())
        return all
    }

    /// Lookup a persistence label against known malware
    public static func checkPersistenceLabel(_ label: String) -> ThreatIndicator? {
        MalwarePersistence.indicators().first {
            $0.type == .persistenceLabel && label.contains($0.value)
        }
    }

    /// Lookup a hostname against known C2 infrastructure
    public static func checkHostname(_ hostname: String) -> ThreatIndicator? {
        MalwareC2.indicators().first {
            $0.type == .c2Domain && hostname.contains($0.value)
        }
    }
}
