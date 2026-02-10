import Foundation

/// Type of persistence mechanism discovered on the system
public enum PersistenceType: String, Sendable, Codable, CaseIterable {
    case launchDaemon = "Launch Daemon"
    case launchAgent = "Launch Agent"
    case loginItem = "Login Item"
    case cronJob = "Cron Job"
    case kernelExtension = "Kernel Extension"
    case systemExtension = "System Extension"
    case browserExtension = "Browser Extension"
    case authorizationPlugin = "Authorization Plugin"
    case loginHook = "Login/Logout Hook"
    case startupScript = "Startup Script"
    case shellConfig = "Shell Config"
    case dylibInsert = "DYLD_INSERT"
    case periodicScript = "Periodic Script"

    public var icon: String {
        switch self {
        case .launchDaemon: return "gear.badge"
        case .launchAgent: return "person.badge.clock"
        case .loginItem: return "arrow.right.to.line.compact"
        case .cronJob: return "clock.badge"
        case .kernelExtension: return "cpu"
        case .systemExtension: return "puzzlepiece.extension"
        case .browserExtension: return "globe"
        case .authorizationPlugin: return "lock.open"
        case .loginHook: return "terminal"
        case .startupScript: return "text.page"
        case .shellConfig: return "chevron.left.forwardslash.chevron.right"
        case .dylibInsert: return "syringe"
        case .periodicScript: return "calendar.badge.clock"
        }
    }
}

/// Signing status of a persistence item's binary
public enum SigningStatus: String, Sendable, Codable {
    case apple = "Apple"
    case appStore = "App Store"
    case devID = "Developer ID"
    case adHoc = "Ad Hoc"
    case unsigned = "Unsigned"
    case unknown = "Unknown"
    case invalid = "Invalid"
}

/// A single persistence item found on the system.
/// Everything is audited — nothing gets a pass.
/// Evidence accumulates upward to show how concerning an item is.
public struct PersistenceItem: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let type: PersistenceType
    public let name: String
    public let path: String
    public let binaryPath: String?
    public let signingStatus: SigningStatus
    public let signingIdentifier: String?
    public let isAppleSigned: Bool
    /// Context tag: this item ships with stock macOS 26.2 per IPSW.
    /// Informational only — does NOT affect suspicion score.
    public let isBaselineItem: Bool
    /// Evidence that raised concern. Empty = no flags, still visible.
    public let evidence: [Evidence]

    // Derived from evidence — backward compatible with views
    public let isSuspicious: Bool
    public let suspicionReasons: [String]

    /// Sum of evidence weights, clamped [0, 1]
    public var suspicionScore: Double {
        min(evidence.reduce(0.0) { $0 + $1.weight }, 1.0)
    }

    /// Severity derived from score
    public var severity: AnomalySeverity { severityFromScore(suspicionScore) }

    public init(
        id: UUID = UUID(),
        type: PersistenceType,
        name: String,
        path: String,
        binaryPath: String? = nil,
        signingStatus: SigningStatus = .unknown,
        signingIdentifier: String? = nil,
        isAppleSigned: Bool = false,
        isBaselineItem: Bool = false,
        evidence: [Evidence] = []
    ) {
        self.id = id
        self.type = type
        self.name = name
        self.path = path
        self.binaryPath = binaryPath
        self.signingStatus = signingStatus
        self.signingIdentifier = signingIdentifier
        self.isAppleSigned = isAppleSigned
        self.isBaselineItem = isBaselineItem
        self.evidence = evidence
        self.isSuspicious = !evidence.isEmpty
        self.suspicionReasons = evidence.map(\.factor)
    }
}
