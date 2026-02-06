import Foundation

/// Protocol for fetching process data from various sources.
/// Enables dependency injection and testing with mock implementations.
public protocol ProcessDataSourceProtocol: Sendable {
    /// Fetch all running processes
    /// - Returns: Array of process data (JSON encoded ProcessInfo)
    func fetchProcesses() async throws -> [Data]

    /// Fetch a specific process by PID
    /// - Parameter pid: The process ID to fetch
    /// - Returns: Process data if found, nil otherwise
    func fetchProcess(pid: Int32) async throws -> Data?

    /// Get the data source status
    /// - Returns: Status dictionary with connection info
    func getStatus() async throws -> [String: Any]
}
