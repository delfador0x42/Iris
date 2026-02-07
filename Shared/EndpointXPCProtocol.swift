import Foundation

/// XPC protocol for communication between the main app and the Endpoint Security Extension.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol EndpointXPCProtocol {

    // MARK: - Process Monitoring

    func getProcesses(reply: @escaping ([Data]) -> Void)
    func getProcess(pid: Int32, reply: @escaping (Data?) -> Void)

    // MARK: - Event History

    func getRecentEvents(limit: Int, reply: @escaping ([Data]) -> Void)

    // MARK: - Extension Control

    func getStatus(reply: @escaping ([String: Any]) -> Void)
    func isEndpointSecurityAvailable(reply: @escaping (Bool) -> Void)
}

// MARK: - Service Names

public enum EndpointXPCService {
    private static let teamID = "99HGW2AR62"
    private static let baseServiceName = "com.wudan.iris.endpoint.xpc"

    public static var extensionServiceName: String {
        "\(teamID).\(baseServiceName)"
    }

    public static var appGroupIdentifier: String {
        "group.com.wudan.iris"
    }
}
