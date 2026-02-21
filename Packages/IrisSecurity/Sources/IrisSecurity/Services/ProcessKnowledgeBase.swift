import Foundation

/// Static knowledge about macOS processes — what they are, why they exist.
/// O(1) lookup by process name. Used to provide "why is this running" context.
public enum ProcessKnowledgeBase {

    public struct Info: Sendable {
        public let description: String
        public let category: Category
        public let subsystem: String
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
}
