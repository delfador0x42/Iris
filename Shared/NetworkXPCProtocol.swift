import Foundation

/// XPC protocol for communication between the main app and the Network Extension.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol NetworkXPCProtocol {

    // MARK: - Connection Monitoring

    func getConnections(reply: @escaping ([Data]) -> Void)
    func getConnections(forPid pid: Int32, reply: @escaping ([Data]) -> Void)

    // MARK: - Rule Management

    func getRules(reply: @escaping ([Data]) -> Void)
    func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)
    func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)
    func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void)
    func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void)
    func cleanupExpiredRules(reply: @escaping (Int) -> Void)

    // MARK: - Extension Control

    func getStatus(reply: @escaping ([String: Any]) -> Void)
    func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)

    // MARK: - Raw Data Capture

    func getConnectionRawData(_ connectionId: String, reply: @escaping (Data?, Data?) -> Void)
    func setCaptureMemoryBudget(_ bytes: Int, reply: @escaping (Bool) -> Void)
    func getCaptureStats(reply: @escaping ([String: Any]) -> Void)
}

// MARK: - Service Names

public enum NetworkXPCService {
    private static let teamID = "99HGW2AR62"
    private static let baseServiceName = "com.wudan.iris.network.xpc"

    public static var extensionServiceName: String {
        "\(teamID).\(baseServiceName)"
    }

    public static var appGroupIdentifier: String {
        "group.com.wudan.iris"
    }
}
