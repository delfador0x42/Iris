import Foundation

/// A detected change to the filesystem
public struct FileSystemChange: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let path: String
    public let changeType: ChangeType
    public let severity: AnomalySeverity
    public let details: String
    public let oldHash: String?
    public let newHash: String?
    public let timestamp: Date

    public enum ChangeType: String, Sendable, Codable {
        case created = "Created"
        case modified = "Modified"
        case deleted = "Deleted"
        case permissionsChanged = "Permissions Changed"
    }

    public init(
        id: UUID = UUID(),
        path: String,
        changeType: ChangeType,
        severity: AnomalySeverity,
        details: String,
        oldHash: String? = nil,
        newHash: String? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.path = path
        self.changeType = changeType
        self.severity = severity
        self.details = details
        self.oldHash = oldHash
        self.newHash = newHash
        self.timestamp = timestamp
    }
}
