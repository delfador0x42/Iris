import Foundation

/// Transport protocol type for captured flows.
public enum ProxyFlowType: String, Codable, Sendable, Hashable {
  case http
  case https
  case tcp
  case udp
}

/// XPC protocol for communication between the main app and the Proxy Extension.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol ProxyXPCProtocol {
  func getStatus(reply: @escaping ([String: Any]) -> Void)
  func getFlows(reply: @escaping ([Data]) -> Void)
  /// Delta fetch: returns only flows with sequenceNumber > sinceSeq.
  func getFlowsSince(_ sinceSeq: UInt64, reply: @escaping (UInt64, [Data]) -> Void)
  func getFlow(_ flowId: String, reply: @escaping (Data?) -> Void)
  func clearFlows(reply: @escaping (Bool) -> Void)
  func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
  func isInterceptionEnabled(reply: @escaping (Bool) -> Void)
  /// Send CA certificate and private key to the extension for TLS MITM.
  func setCA(_ certData: Data, keyData: Data, reply: @escaping (Bool) -> Void)
  /// Update byte counts and completion status for a flow.
  func updateFlowBytes(
    _ flowId: String, bytesIn: Int64, bytesOut: Int64,
    ended: Bool, error: String?, reply: @escaping (Bool) -> Void)
}

// MARK: - XPC Interface Helper

public enum ProxyXPCInterface {
  public static let serviceName = "99HGW2AR62.com.wudan.iris.proxy.xpc"

  public static func createInterface() -> NSXPCInterface {
    return NSXPCInterface(with: ProxyXPCProtocol.self)
  }

  public static func createConnection() -> NSXPCConnection {
    let connection = NSXPCConnection(machServiceName: serviceName, options: [])
    connection.remoteObjectInterface = createInterface()
    return connection
  }
}
