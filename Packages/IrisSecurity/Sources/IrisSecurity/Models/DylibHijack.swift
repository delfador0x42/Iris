import Foundation

/// Type of dylib hijack vulnerability or active hijack
public enum HijackType: String, Sendable, Codable {
    case rpathHijack = "@rpath Hijack"
    case weakHijack = "Weak Dylib Hijack"
    case rpathVulnerable = "@rpath Vulnerable"
    case weakVulnerable = "Weak Dylib Vulnerable"
    case dylibProxy = "Dylib Proxy (Re-export)"
}

/// A detected dylib hijack or vulnerability
public struct DylibHijack: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let type: HijackType
    public let binaryPath: String
    public let binaryName: String
    public let dylibPath: String
    public let isActiveHijack: Bool
    public let details: String

    public init(
        id: UUID = UUID(),
        type: HijackType,
        binaryPath: String,
        dylibPath: String,
        isActiveHijack: Bool,
        details: String
    ) {
        self.id = id
        self.type = type
        self.binaryPath = binaryPath
        self.binaryName = URL(fileURLWithPath: binaryPath).lastPathComponent
        self.dylibPath = dylibPath
        self.isActiveHijack = isActiveHijack
        self.details = details
    }
}
