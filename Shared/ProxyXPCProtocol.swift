import Foundation

/// Transport protocol type for captured flows.
public enum ProxyFlowType: String, Codable, Sendable, Hashable {
  case http
  case https
  case tcp
  case udp
}

/// XPC protocol for communication between the main app and the Proxy Extension.
/// Unified protocol: handles flows, DNS-over-HTTPS, connection monitoring, and firewall rules.
/// Single source of truth — compiled into BOTH the app and extension targets.
@objc public protocol ProxyXPCProtocol {

  // MARK: - Flow Monitoring

  func getStatus(reply: @escaping ([String: Any]) -> Void)
  /// Delta fetch: returns only flows with sequenceNumber > sinceSeq.
  func getFlowsSince(_ sinceSeq: UInt64, reply: @escaping (UInt64, [Data]) -> Void)
  func clearFlows(reply: @escaping (Bool) -> Void)
  func setInterceptionEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
  /// Send CA certificate and private key to the extension for TLS MITM.
  func setCA(_ certData: Data, keyData: Data, reply: @escaping (Bool) -> Void)

  // MARK: - DNS-over-HTTPS

  /// Delta fetch: returns only queries with sequenceNumber > sinceSeq.
  func getDNSQueriesSince(_ sinceSeq: UInt64, limit: Int, reply: @escaping (UInt64, [Data]) -> Void)
  func clearDNSQueries(reply: @escaping (Bool) -> Void)
  func setDNSEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
  func isDNSEnabled(reply: @escaping (Bool) -> Void)
  func setDNSServer(_ serverName: String, reply: @escaping (Bool) -> Void)
  func getDNSServer(reply: @escaping (String) -> Void)
  func getDNSStatistics(reply: @escaping ([String: Any]) -> Void)

  // MARK: - Connection Monitoring (from Network Filter)

  func getConnections(reply: @escaping ([Data]) -> Void)

  // MARK: - Firewall Rules (from Network Filter)

  func getRules(reply: @escaping ([Data]) -> Void)
  func addRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)
  func updateRule(_ ruleData: Data, reply: @escaping (Bool, String?) -> Void)
  func removeRule(_ ruleId: String, reply: @escaping (Bool) -> Void)
  func toggleRule(_ ruleId: String, reply: @escaping (Bool) -> Void)
  func setFilteringEnabled(_ enabled: Bool, reply: @escaping (Bool) -> Void)
  func isFilteringEnabled(reply: @escaping (Bool) -> Void)

  // MARK: - Raw Data Capture

  func getConnectionRawData(_ connectionId: String, reply: @escaping (Data?, Data?) -> Void)
  func getConnectionConversation(_ connectionId: String, reply: @escaping (Data?) -> Void)
  func setCaptureMemoryBudget(_ bytes: Int, reply: @escaping (Bool) -> Void)
  func getCaptureStats(reply: @escaping ([String: Any]) -> Void)
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
