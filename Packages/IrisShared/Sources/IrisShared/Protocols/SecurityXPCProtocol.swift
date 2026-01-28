import Foundation
import Security

// MARK: - XPC Protocol Keys

/// Keys used in XPC dictionaries for communication
public enum SecurityXPCKey {
    public static let processId = "pid"
    public static let processPath = "path"
    public static let connectionId = "connectionId"
    public static let ruleId = "ruleId"
    public static let action = "action"
    public static let error = "error"
}

// MARK: - XPC Protocol

/// Protocol for communication between the main app and the security extension
/// Note: This uses NSObjectProtocol for XPC compatibility
@objc public protocol SecurityXPCProtocol {

    // MARK: - Process Monitoring

    /// Get all currently tracked processes
    /// - Parameter reply: Callback with array of encoded ProcessInfo data
    func getProcesses(reply: @escaping ([Data]) -> Void)

    /// Get a specific process by PID
    /// - Parameters:
    ///   - pid: Process ID to look up
    ///   - reply: Callback with encoded ProcessInfo data or nil
    func getProcess(pid: Int32, reply: @escaping (Data?) -> Void)

    // MARK: - Connection Monitoring

    /// Get all active network connections
    /// - Parameter reply: Callback with array of encoded NetworkConnection data
    func getConnections(reply: @escaping ([Data]) -> Void)

    /// Get connections for a specific process
    /// - Parameters:
    ///   - pid: Process ID to filter by
    ///   - reply: Callback with array of encoded NetworkConnection data
    func getConnections(forPid pid: Int32, reply: @escaping ([Data]) -> Void)

    // MARK: - Rule Management

    /// Get all security rules
    /// - Parameter reply: Callback with array of encoded SecurityRule data
    func getRules(reply: @escaping ([Data]) -> Void)

    /// Add a new security rule
    /// - Parameters:
    ///   - ruleData: Encoded SecurityRule data
    ///   - reply: Callback with success status and optional error message
    func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)

    /// Update an existing rule
    /// - Parameters:
    ///   - ruleData: Encoded SecurityRule data with existing ID
    ///   - reply: Callback with success status and optional error message
    func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)

    /// Remove a rule by ID
    /// - Parameters:
    ///   - ruleId: UUID string of the rule to remove
    ///   - reply: Callback with success status
    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void)

    /// Toggle a rule's enabled state
    /// - Parameters:
    ///   - ruleId: UUID string of the rule to toggle
    ///   - reply: Callback with success status
    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void)

    /// Clear all expired rules
    /// - Parameter reply: Callback with number of rules removed
    func cleanupExpiredRules(reply: @escaping (Int) -> Void)

    // MARK: - Extension Control

    /// Get extension status information
    /// - Parameter reply: Callback with status dictionary
    func getStatus(reply: @escaping ([String: Any]) -> Void)

    /// Enable or disable network filtering
    /// - Parameters:
    ///   - enabled: Whether filtering should be enabled
    ///   - reply: Callback with success status
    func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
}

// MARK: - Reverse XPC Protocol (Extension → App)

/// Protocol for the extension to notify the main app of events
@objc public protocol SecurityXPCClientProtocol {

    /// Notify of a new network connection that needs a decision
    /// - Parameters:
    ///   - connectionData: Encoded NetworkConnection data
    ///   - processData: Encoded ProcessInfo data
    ///   - reply: Callback with rule action to apply
    func alertNewConnection(
        _ connectionData: Data,
        process processData: Data,
        reply: @escaping (String) -> Void  // "allow" or "block"
    )

    /// Notify that rules have changed
    func rulesDidChange()

    /// Notify of extension status change
    /// - Parameter status: New status dictionary
    func statusDidChange(_ status: [String: Any])
}

// MARK: - XPC Service Names

public enum SecurityXPCService {
    /// Base service name (without team ID prefix)
    private static let baseServiceName = "com.wudan.iris.security.xpc"

    /// Mach service name for the security extension (includes team ID prefix)
    public static var extensionServiceName: String {
        guard let teamID = teamIdentifierPrefix else {
            // Fallback for development - this shouldn't happen with proper signing
            return baseServiceName
        }
        return "\(teamID)\(baseServiceName)"
    }

    /// App group identifier for shared data
    public static var appGroupIdentifier: String {
        guard let teamID = teamIdentifierPrefix else {
            return "group.com.wudan.iris"
        }
        return "\(teamID)\(baseServiceName)"
    }

    /// Gets the team identifier prefix from the app's entitlements
    private static var teamIdentifierPrefix: String? {
        // Read the code signing entitlements to get the team ID
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else {
            return nil
        }

        // Convert to static code for signing info
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode = staticCode else {
            return nil
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any],
              let teamID = signingInfo["teamid"] as? String else {
            return nil
        }

        return "\(teamID)."
    }
}
