import Foundation

/// A recorded process lifecycle event for the history buffer
struct ESProcessEvent: Codable {
    let eventType: EventType
    let process: ESProcessInfo
    let timestamp: Date

    enum EventType: String, Codable {
        case exec
        case fork
        case exit
        case signal
        case csInvalidated
    }
}

/// Process info model from Endpoint Security events.
/// Encoded via JSON over XPC to the main app.
struct ESProcessInfo: Codable {
    let pid: Int32
    let ppid: Int32
    let responsiblePid: Int32
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

// MARK: - Security Events (file access, privilege, injection, system changes)

/// Categories of security-relevant events beyond process lifecycle
enum SecurityEventType: String, Codable {
    // File operations
    case fileOpen, fileWrite, fileUnlink, fileRename, fileSetExtattr
    // Privilege escalation
    case setuid, setgid, sudo
    // Code injection
    case remoteThreadCreate, getTask, ptrace
    // Memory/Execution (code injection detection)
    case mmap, mprotect, procSuspendResume
    // System changes
    case kextLoad, mount, tccModify, xpcConnect, btmLaunchItemAdd
    // Authentication / Authorization
    case sshLogin, xprotectMalwareDetected
    case authExec, authOpen
}

/// A security event captured by Endpoint Security.
/// Separate from process lifecycle events to avoid noise drowning out
/// important detections. Uses sequence numbers for delta XPC fetch.
struct ESSecurityEvent: Codable, Identifiable {
    let id: UUID
    let eventType: SecurityEventType
    let process: ESProcessInfo
    let timestamp: Date
    let targetPath: String?
    let targetProcess: ESProcessInfo?
    let detail: String?
    let parentPath: String?
    let parentName: String?
    var sequenceNumber: UInt64

    init(
        eventType: SecurityEventType,
        process: ESProcessInfo,
        timestamp: Date = Date(),
        targetPath: String? = nil,
        targetProcess: ESProcessInfo? = nil,
        detail: String? = nil,
        parentPath: String? = nil,
        parentName: String? = nil,
        sequenceNumber: UInt64 = 0
    ) {
        self.id = UUID()
        self.eventType = eventType
        self.process = process
        self.timestamp = timestamp
        self.targetPath = targetPath
        self.targetProcess = targetProcess
        self.detail = detail
        self.parentPath = parentPath
        self.parentName = parentName
        self.sequenceNumber = sequenceNumber
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
