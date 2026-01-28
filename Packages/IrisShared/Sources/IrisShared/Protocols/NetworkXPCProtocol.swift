import Foundation

// MARK: - Network Extension XPC Protocol

/// Protocol for communication between the main app and the Network Extension
@objc public protocol NetworkXPCProtocol {

    // MARK: - Connection Monitoring

    /// Get all active network connections
    func getConnections(reply: @escaping ([Data]) -> Void)

    /// Get connections for a specific process
    func getConnections(forPid pid: Int32, reply: @escaping ([Data]) -> Void)

    // MARK: - Rule Management

    /// Get all security rules
    func getRules(reply: @escaping ([Data]) -> Void)

    /// Add a new security rule
    func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)

    /// Update an existing rule
    func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)

    /// Remove a rule by ID
    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void)

    /// Toggle a rule's enabled state
    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void)

    /// Clear all expired rules
    func cleanupExpiredRules(reply: @escaping (Int) -> Void)

    // MARK: - Extension Control

    /// Get extension status information
    func getStatus(reply: @escaping ([String: Any]) -> Void)

    /// Enable or disable network filtering
    func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
}

// MARK: - Network XPC Service Names

public enum NetworkXPCService {
    /// Team identifier
    private static let teamID = "99HGW2AR62"

    /// Base service name
    private static let baseServiceName = "com.wudan.iris.network.xpc"

    /// Full Mach service name for the network extension
    public static var extensionServiceName: String {
        "\(teamID).\(baseServiceName)"
    }

    /// App group identifier for shared data
    public static var appGroupIdentifier: String {
        "group.com.wudan.iris"
    }
}
