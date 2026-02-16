import Foundation

/// Severity of a detected process anomaly
public enum AnomalySeverity: Int, Sendable, Codable, Comparable {
    case low = 0
    case medium = 1
    case high = 2
    case critical = 3

    public static func < (lhs: AnomalySeverity, rhs: AnomalySeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        case .critical: return "Critical"
        }
    }
}

/// A suspicious behavior or anomaly detected in a running process
public struct ProcessAnomaly: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let pid: pid_t
    public let processName: String
    public let processPath: String
    public let parentPID: pid_t
    public let parentName: String
    public let technique: String
    public let description: String
    public let severity: AnomalySeverity
    public let mitreID: String?
    public let timestamp: Date
    /// Which scanner module produced this finding (e.g. "process_integrity")
    public let scannerId: String
    /// How the finding was discovered (e.g. "task_info(TASK_DYLD_INFO)")
    public let enumMethod: String
    /// Supporting evidence lines (dylib paths, flag values, hashes, etc.)
    public let evidence: [String]

    public init(
        id: UUID = UUID(),
        pid: pid_t,
        processName: String,
        processPath: String,
        parentPID: pid_t,
        parentName: String,
        technique: String,
        description: String,
        severity: AnomalySeverity,
        mitreID: String? = nil,
        timestamp: Date = Date(),
        scannerId: String = "",
        enumMethod: String = "",
        evidence: [String] = []
    ) {
        self.id = id
        self.pid = pid
        self.processName = processName
        self.processPath = processPath
        self.parentPID = parentPID
        self.parentName = parentName
        self.technique = technique
        self.description = description
        self.severity = severity
        self.mitreID = mitreID
        self.timestamp = timestamp
        self.scannerId = scannerId
        self.enumMethod = enumMethod
        self.evidence = evidence
    }

    /// Factory for filesystem-based findings (no running process).
    public static func filesystem(
        name: String, path: String,
        technique: String, description: String,
        severity: AnomalySeverity, mitreID: String,
        scannerId: String = "", enumMethod: String = "", evidence: [String] = []
    ) -> ProcessAnomaly {
        ProcessAnomaly(
            pid: 0, processName: name, processPath: path,
            parentPID: 0, parentName: "",
            technique: technique, description: description,
            severity: severity, mitreID: mitreID,
            scannerId: scannerId, enumMethod: enumMethod, evidence: evidence
        )
    }

    /// Factory for process-based findings without parent info.
    public static func forProcess(
        pid: pid_t, name: String, path: String,
        technique: String, description: String,
        severity: AnomalySeverity, mitreID: String,
        scannerId: String = "", enumMethod: String = "", evidence: [String] = []
    ) -> ProcessAnomaly {
        ProcessAnomaly(
            pid: pid, processName: name, processPath: path,
            parentPID: 0, parentName: "",
            technique: technique, description: description,
            severity: severity, mitreID: mitreID,
            scannerId: scannerId, enumMethod: enumMethod, evidence: evidence
        )
    }
}
