import Foundation

/// Reasons why a process might be suspicious
public enum SuspicionReason: String, Codable, CaseIterable, Sendable {
    case unsigned = "Unsigned"
    case adHocSigned = "Ad-hoc signed"
    case suspiciousLocation = "Suspicious location"
    case hiddenProcess = "Hidden process"
    case notAppleSigned = "Not Apple signed"
    case noManPage = "No man page"
    case highCPU = "High CPU usage"
    case deletedBinary = "Deleted binary"
    case recentlySpawned = "Recently spawned"

    public var description: String { rawValue }

    public var severity: SuspicionSeverity {
        switch self {
        case .unsigned, .suspiciousLocation, .deletedBinary: return .high
        case .adHocSigned, .hiddenProcess, .highCPU: return .medium
        case .notAppleSigned, .noManPage, .recentlySpawned: return .low
        }
    }
}

/// Severity level for suspicion indicators
public enum SuspicionSeverity: Int, Comparable, Sendable {
    case low = 1
    case medium = 2
    case high = 3

    public static func < (lhs: SuspicionSeverity, rhs: SuspicionSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        }
    }
}

/// Represents a process captured by Endpoint Security
public struct ProcessInfo: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let pid: Int32
    public let ppid: Int32
    public let path: String
    public let name: String
    public let arguments: [String]
    public let userId: UInt32
    public let groupId: UInt32
    public let codeSigningInfo: CodeSigningInfo?
    public let timestamp: Date
    /// Whether this process has a man page (nil if not checked yet)
    public var hasManPage: Bool?
    /// CPU, memory, thread, and file descriptor metrics
    public var resources: ProcessResourceInfo?

    public init(
        id: UUID = UUID(),
        pid: Int32,
        ppid: Int32,
        path: String,
        name: String,
        arguments: [String] = [],
        userId: UInt32,
        groupId: UInt32,
        codeSigningInfo: CodeSigningInfo? = nil,
        timestamp: Date = Date(),
        hasManPage: Bool? = nil,
        resources: ProcessResourceInfo? = nil
    ) {
        self.id = id
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.name = name
        self.arguments = arguments
        self.userId = userId
        self.groupId = groupId
        self.codeSigningInfo = codeSigningInfo
        self.timestamp = timestamp
        self.hasManPage = hasManPage
        self.resources = resources
    }

    /// Code signing information for a process
    public struct CodeSigningInfo: Sendable, Codable, Equatable {
        public let teamId: String?
        public let signingId: String?
        public let flags: UInt32
        public let isAppleSigned: Bool
        public let isPlatformBinary: Bool

        public init(
            teamId: String?,
            signingId: String?,
            flags: UInt32,
            isAppleSigned: Bool,
            isPlatformBinary: Bool
        ) {
            self.teamId = teamId
            self.signingId = signingId
            self.flags = flags
            self.isAppleSigned = isAppleSigned
            self.isPlatformBinary = isPlatformBinary
        }

        /// Human-readable signer description
        public var signerDescription: String {
            if isAppleSigned {
                return isPlatformBinary ? "Apple (Platform)" : "Apple"
            } else if let teamId = teamId {
                return "Developer ID (\(teamId))"
            } else if signingId != nil {
                return "Ad-hoc signed"
            } else {
                return "Unsigned"
            }
        }
    }

    /// Bundle name extracted from path if available
    public var bundleName: String? {
        guard path.contains(".app/") else { return nil }
        let components = path.components(separatedBy: ".app/")
        if let appPath = components.first {
            return URL(fileURLWithPath: appPath + ".app").lastPathComponent
        }
        return nil
    }

    /// Display name (bundle name or process name)
    public var displayName: String {
        bundleName ?? name
    }

    // MARK: - Suspicion Detection

    /// Locations commonly used for staging malware
    private static let suspiciousLocations = [
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "/private/var/tmp/",
        "/Users/Shared/",
        "/Library/Caches/",
        "/.Trash/",
        "/dev/shm/"
    ]

    /// Whether the process is running from a suspicious location
    private var isFromSuspiciousLocation: Bool {
        Self.suspiciousLocations.contains { path.hasPrefix($0) }
    }

    /// Whether the process name indicates it's hidden
    private var isHiddenProcess: Bool {
        name.hasPrefix(".")
    }

    // MARK: - CodingKeys

    /// Exclude ephemeral properties from Codable — they're computed app-side
    enum CodingKeys: String, CodingKey {
        case id, pid, ppid, path, name, arguments, userId, groupId
        case codeSigningInfo, timestamp
    }

    /// Cached suspicion reasons (call `refreshSuspicion()` to update).
    public var suspicionReasons: [SuspicionReason] = []

    /// Whether this process should be highlighted as suspicious
    public var isSuspicious: Bool { !suspicionReasons.isEmpty }

    /// The highest severity level among all suspicion reasons
    public var highestSeverity: SuspicionSeverity? {
        suspicionReasons.map(\.severity).max()
    }

    /// Recompute suspicion reasons. Call once when data changes, not on every view render.
    public mutating func refreshSuspicion() {
        var reasons: [SuspicionReason] = []
        if let csInfo = codeSigningInfo {
            if csInfo.signingId == nil && csInfo.teamId == nil && !csInfo.isAppleSigned {
                reasons.append(.unsigned)
            } else if csInfo.teamId == nil && csInfo.signingId != nil && !csInfo.isAppleSigned {
                reasons.append(.adHocSigned)
            } else if !csInfo.isAppleSigned && !csInfo.isPlatformBinary {
                reasons.append(.notAppleSigned)
            }
        } else {
            reasons.append(.unsigned)
        }
        if isFromSuspiciousLocation { reasons.append(.suspiciousLocation) }
        if isHiddenProcess { reasons.append(.hiddenProcess) }
        // Only flag noManPage for non-Apple binaries — most Apple daemons lack man pages
        let isApple = codeSigningInfo?.isAppleSigned == true || codeSigningInfo?.isPlatformBinary == true
        if hasManPage == false && !isApple { reasons.append(.noManPage) }
        if let res = resources, res.cpuUsagePercent > 80 { reasons.append(.highCPU) }
        if !FileManager.default.fileExists(atPath: path) { reasons.append(.deletedBinary) }
        if Date().timeIntervalSince(timestamp) < 10 { reasons.append(.recentlySpawned) }
        suspicionReasons = reasons
    }
}
