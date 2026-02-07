import Foundation

/// Result status of a security configuration check
public enum CheckStatus: String, Sendable, Codable {
    case pass
    case fail
    case warning
    case unknown
}

/// Severity level for security checks
public enum CheckSeverity: Int, Sendable, Codable, Comparable {
    case info = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    public static func < (lhs: CheckSeverity, rhs: CheckSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .info: return "Info"
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        case .critical: return "Critical"
        }
    }

    /// Weight used for grade computation
    var weight: Int {
        switch self {
        case .info: return 2
        case .low: return 5
        case .medium: return 10
        case .high: return 15
        case .critical: return 20
        }
    }
}

/// A single security configuration check result
public struct SecurityCheck: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let category: SecurityCategory
    public let name: String
    public let description: String
    public let status: CheckStatus
    public let severity: CheckSeverity
    public let remediation: String?

    public init(
        id: UUID = UUID(),
        category: SecurityCategory,
        name: String,
        description: String,
        status: CheckStatus,
        severity: CheckSeverity,
        remediation: String? = nil
    ) {
        self.id = id
        self.category = category
        self.name = name
        self.description = description
        self.status = status
        self.severity = severity
        self.remediation = remediation
    }
}
