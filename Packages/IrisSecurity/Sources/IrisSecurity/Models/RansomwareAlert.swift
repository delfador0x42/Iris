import Foundation

/// A ransomware detection alert from file entropy analysis
public struct RansomwareAlert: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let processID: pid_t
    public let processName: String
    public let processPath: String
    public let encryptedFiles: [String]
    public let entropy: Double
    public let timestamp: Date

    public init(
        id: UUID = UUID(),
        processID: pid_t,
        processName: String,
        processPath: String,
        encryptedFiles: [String],
        entropy: Double,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.processID = processID
        self.processName = processName
        self.processPath = processPath
        self.encryptedFiles = encryptedFiles
        self.entropy = entropy
        self.timestamp = timestamp
    }
}
