import Foundation

/// Static knowledge about macOS processes and network destinations.
/// O(1) lookup by process name. Used by justification engines.
public enum ProcessKnowledgeBase {

    public struct Info: Sendable {
        public let description: String
        public let category: Category
        public let subsystem: String
        public let expectedConnections: [String]   // hostname glob patterns
        public let isSystemCritical: Bool

        public init(description: String, category: Category, subsystem: String,
                    expectedConnections: [String] = [], isSystemCritical: Bool = false) {
            self.description = description
            self.category = category
            self.subsystem = subsystem
            self.expectedConnections = expectedConnections
            self.isSystemCritical = isSystemCritical
        }
    }

    public enum Category: String, Sendable {
        case kernel = "Kernel"
        case systemDaemon = "System Daemon"
        case systemAgent = "System Agent"
        case systemService = "System Service"
        case security = "Security"
        case network = "Network"
        case storage = "Storage"
        case graphics = "Graphics"
        case media = "Media"
        case devTool = "Dev Tool"
        case userApp = "User App"
        case unknown = "Unknown"
    }

    /// Lookup by process name (basename without extension).
    public static func lookup(_ name: String) -> Info? {
        knownProcesses[name]
    }

    /// Lookup by full path — extracts basename automatically.
    public static func lookup(path: String) -> Info? {
        let name = (path as NSString).lastPathComponent
        return knownProcesses[name]
    }

    /// Returns a one-line description or nil if unknown.
    public static func describe(_ name: String) -> String? {
        knownProcesses[name]?.description
    }

    /// Whether this process name is a known macOS component.
    public static func isKnown(_ name: String) -> Bool {
        knownProcesses[name] != nil
    }

    /// Check if a connection is expected for a given process.
    public static func isExpectedConnection(_ processName: String, host: String) -> Bool {
        guard let info = knownProcesses[processName] else { return false }
        let h = host.lowercased()
        return info.expectedConnections.contains { pattern in
            matchGlob(pattern: pattern, string: h)
        }
    }

    // MARK: - Destination Knowledge

    public struct DestinationInfo: Sendable {
        public let pattern: String
        public let owner: String
        public let purpose: String
        public let category: DestinationCategory
        public let isTelemetry: Bool
        public let isEssential: Bool
    }

    public enum DestinationCategory: String, Sendable {
        case appleService = "Apple Service"
        case cdn = "CDN"
        case analytics = "Analytics"
        case cloudProvider = "Cloud Provider"
        case securityService = "Security Service"
        case developerService = "Developer Service"
        case dns = "DNS"
        case unknown = "Unknown"
    }

    /// Lookup network destination by hostname.
    public static func lookupDestination(_ hostname: String) -> DestinationInfo? {
        let h = hostname.lowercased()
        return knownDestinations.first { matchGlob(pattern: $0.pattern, string: h) }
    }

    // MARK: - Glob Matching

    static func matchGlob(pattern: String, string: String) -> Bool {
        if pattern == string { return true }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(1))
            return string.hasSuffix(suffix) || string == String(suffix.dropFirst(1))
        }
        if pattern.hasSuffix("*") {
            return string.hasPrefix(String(pattern.dropLast(1)))
        }
        return false
    }
}
