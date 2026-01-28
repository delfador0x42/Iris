import Foundation

// MARK: - Endpoint Security Extension XPC Protocol

/// Protocol for communication between the main app and the Endpoint Security Extension
@objc public protocol EndpointXPCProtocol {

    // MARK: - Process Monitoring

    /// Get all currently tracked processes
    func getProcesses(reply: @escaping ([Data]) -> Void)

    /// Get a specific process by PID
    func getProcess(pid: Int32, reply: @escaping (Data?) -> Void)

    // MARK: - Extension Control

    /// Get extension status information
    func getStatus(reply: @escaping ([String: Any]) -> Void)
}

// MARK: - Endpoint XPC Service Names

public enum EndpointXPCService {
    /// Team identifier
    private static let teamID = "99HGW2AR62"

    /// Base service name
    private static let baseServiceName = "com.wudan.iris.endpoint.xpc"

    /// Full Mach service name for the endpoint extension
    public static var extensionServiceName: String {
        "\(teamID).\(baseServiceName)"
    }

    /// App group identifier for shared data
    public static var appGroupIdentifier: String {
        "group.com.wudan.iris"
    }
}
