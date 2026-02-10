import Foundation

/// Process info model from Endpoint Security events.
/// Encoded via JSON over XPC to the main app.
struct ESProcessInfo: Codable {
    let id: UUID
    let pid: Int32
    let ppid: Int32
    let path: String
    let name: String
    let arguments: [String]
    let userId: UInt32
    let groupId: UInt32
    let codeSigningInfo: CodeSigningInfo?
    let timestamp: Date

    struct CodeSigningInfo: Codable {
        let teamId: String?
        let signingId: String?
        let flags: UInt32
        let isAppleSigned: Bool
        let isPlatformBinary: Bool
    }
}

// MARK: - Error Types

enum ESClientError: Error, LocalizedError {
    case clientCreationFailed(String)
    case subscriptionFailed
    case notRunning

    var errorDescription: String? {
        switch self {
        case .clientCreationFailed(let reason):
            return "Failed to create ES client: \(reason)"
        case .subscriptionFailed:
            return "Failed to subscribe to ES events"
        case .notRunning:
            return "ES client is not running"
        }
    }
}
