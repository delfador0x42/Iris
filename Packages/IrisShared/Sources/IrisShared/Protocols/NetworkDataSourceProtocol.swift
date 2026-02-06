import Foundation

/// Protocol for fetching network data from various sources.
/// Enables dependency injection and testing with mock implementations.
public protocol NetworkDataSourceProtocol: Sendable {
    /// Fetch all active network connections
    /// - Returns: Array of connection data (JSON encoded NetworkConnection)
    func fetchConnections() async throws -> [Data]

    /// Fetch connections for a specific process
    /// - Parameter pid: The process ID to fetch connections for
    /// - Returns: Array of connection data for the process
    func fetchConnections(forPid pid: Int32) async throws -> [Data]

    /// Fetch all security rules
    /// - Returns: Array of rule data (JSON encoded SecurityRule)
    func fetchRules() async throws -> [Data]

    /// Add a new security rule
    /// - Parameter ruleData: JSON encoded rule data
    /// - Returns: Success status and optional error message
    func addRule(_ ruleData: Data) async throws -> (success: Bool, error: String?)

    /// Remove a rule by ID
    /// - Parameter ruleId: The rule ID to remove
    /// - Returns: True if removal succeeded
    func removeRule(_ ruleId: String) async throws -> Bool

    /// Toggle a rule's enabled state
    /// - Parameter ruleId: The rule ID to toggle
    /// - Returns: True if toggle succeeded
    func toggleRule(_ ruleId: String) async throws -> Bool

    /// Get the data source status
    /// - Returns: Status dictionary with connection info
    func getStatus() async throws -> [String: Any]
}
