import Foundation

/// Source of a package installation
public enum PackageSource: String, Sendable, Codable, CaseIterable {
    case homebrew = "Homebrew"
    case appStore = "App Store"
    case pkgutil = "Installer"
    case application = "Application"
}

/// An installed package or application on the system
public struct InstalledPackage: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let version: String?
    public let source: PackageSource
    public let path: String?
    public let bundleId: String?

    public init(
        id: UUID = UUID(),
        name: String,
        version: String? = nil,
        source: PackageSource,
        path: String? = nil,
        bundleId: String? = nil
    ) {
        self.id = id
        self.name = name
        self.version = version
        self.source = source
        self.path = path
        self.bundleId = bundleId
    }

    /// Display string combining name and version
    public var displayVersion: String {
        version ?? "unknown"
    }
}
