import Foundation

/// Process identity from Endpoint Security.
/// This is the universal representation — every ES event flows through it.
/// Extract EVERYTHING the kernel gives us. Every field we skip is a field
/// the adversary can use undetected.
struct ESProcessInfo: Codable, Sendable {
  // Identity
  let pid: Int32
  let ppid: Int32
  let originalPpid: Int32?     // Before reparenting — detects double-fork laundering
  let responsiblePid: Int32
  let processGroupId: Int32?   // Job control group
  let sessionId: Int32?        // Login session — lateral movement grouping

  // Binary
  let path: String
  let name: String
  let cdhash: String?          // 20-byte hex — tamper-proof binary identity

  // Execution context
  let arguments: [String]
  let environment: [String]?   // DYLD_* and suspicious env vars (EXEC only)

  // User
  let userId: UInt32
  let groupId: UInt32

  // Code signing (flattened — always available from es_process_t)
  let codeSigningInfo: CodeSigningInfo?

  // Timing
  let timestamp: Date
  let machTime: UInt64?        // Monotonic nanosecond — forensic ground truth
  let startTime: Double?       // Process start (seconds since epoch from timeval)

  // Flags
  let isESClient: Bool?        // Is this process an ES client? Detect competing EDR/attacker ES
  let ttyPath: String?         // Terminal device — interactive session detection

  struct CodeSigningInfo: Codable, Sendable {
    let teamId: String?
    let signingId: String?
    let flags: UInt32
    let isAppleSigned: Bool
    let isPlatformBinary: Bool
  }
}

// MARK: - Process Lifecycle Event

struct ESProcessEvent: Codable, Sendable {
  let eventType: EventType
  let process: ESProcessInfo
  let timestamp: Date

  enum EventType: String, Codable, Sendable {
    case exec, fork, exit, signal, csInvalidated
  }
}

// MARK: - Security Events

enum SecurityEventType: String, Codable, Sendable {
  // File operations
  case fileOpen, fileWrite, fileUnlink, fileRename, fileSetExtattr
  case fileCreate, fileLink, deleteExtattr, setOwner
  // Anti-forensics
  case fileTruncate, fileUtimes, fileSetMode, fileSetFlags
  // Privilege escalation
  case setuid, setgid, sudo
  // Code injection
  case remoteThreadCreate, getTask, getTaskRead, getTaskInspect, ptrace
  // Memory/Execution
  case mmap, mprotect, procSuspendResume
  // Process introspection (new)
  case procCheck, ptyGrant, ptyClose
  // System changes
  case kextLoad, mount, tccModify, xpcConnect, btmLaunchItemAdd
  // Process integrity
  case csInvalidated, signalSent
  // Authentication / Authorization
  case sshLogin, xprotectMalwareDetected
  case authExec, authOpen
  // Nation-state detection
  case iokitOpen, copyfile
  case uipcBind, uipcConnect
  case authentication, sessionLogin, sessionLogout
}

/// Security event captured by Endpoint Security.
/// Uses monotonic sequence numbers — not UUIDs — for identification.
struct ESSecurityEvent: Codable, Sendable, Identifiable {
  let id: UUID
  let eventType: SecurityEventType
  let process: ESProcessInfo
  let timestamp: Date
  let machTime: UInt64?
  let globalSeqNum: UInt64?    // Kernel global ordering
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
    machTime: UInt64? = nil,
    globalSeqNum: UInt64? = nil,
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
    self.machTime = machTime
    self.globalSeqNum = globalSeqNum
    self.targetPath = targetPath
    self.targetProcess = targetProcess
    self.detail = detail
    self.parentPath = parentPath
    self.parentName = parentName
    self.sequenceNumber = sequenceNumber
  }
}

// MARK: - Errors

enum ESClientError: Error, LocalizedError {
  case clientCreationFailed(String)
  case subscriptionFailed
  case notRunning

  var errorDescription: String? {
    switch self {
    case .clientCreationFailed(let reason): return "ES client creation failed: \(reason)"
    case .subscriptionFailed: return "ES event subscription failed"
    case .notRunning: return "ES client not running"
    }
  }
}
