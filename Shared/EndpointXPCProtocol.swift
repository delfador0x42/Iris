import Foundation

/// XPC protocol for communication between the main app and the Endpoint Security Extension.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol EndpointXPCProtocol {

    // MARK: - Process Monitoring

    func getProcesses(reply: @escaping ([Data]) -> Void)

    // MARK: - Event History

    func getRecentEvents(limit: Int, reply: @escaping ([Data]) -> Void)

    // MARK: - Security Events

    /// Delta fetch: returns security events with sequenceNumber > sinceSeq.
    /// Reply includes the current max sequence number and the new events as JSON Data.
    func getSecurityEventsSince(_ sinceSeq: UInt64, limit: Int, reply: @escaping (UInt64, [Data]) -> Void)

    // MARK: - Extension Control

    func getStatus(reply: @escaping ([String: Any]) -> Void)

    // MARK: - ExecPolicy Configuration

    /// Push threat intel blocklists from main app to extension
    func updateBlocklists(paths: [String], teamIds: [String], signingIds: [String],
                          reply: @escaping (Bool) -> Void)

    /// Toggle enforcement mode (true = enforce, false = audit only)
    func setEnforcementMode(_ enforce: Bool, reply: @escaping (Bool) -> Void)
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
