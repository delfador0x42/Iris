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

/// A single persistence item found on the system
public struct PersistenceItem: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let type: PersistenceType
    public let name: String
    public let path: String
    public let binaryPath: String?
    public let signingStatus: SigningStatus
    public let signingIdentifier: String?
    public let isAppleSigned: Bool
    public let isSuspicious: Bool
    public let suspicionReasons: [String]

    public init(
        id: UUID = UUID(),
        type: PersistenceType,
        name: String,
        path: String,
        binaryPath: String? = nil,
        signingStatus: SigningStatus = .unknown,
        signingIdentifier: String? = nil,
        isAppleSigned: Bool = false,
        isSuspicious: Bool = false,
        suspicionReasons: [String] = []
    ) {
        self.id = id
        self.type = type
        self.name = name
        self.path = path
        self.binaryPath = binaryPath
        self.signingStatus = signingStatus
        self.signingIdentifier = signingIdentifier
        self.isAppleSigned = isAppleSigned
        self.isSuspicious = isSuspicious
        self.suspicionReasons = suspicionReasons
    }
}
