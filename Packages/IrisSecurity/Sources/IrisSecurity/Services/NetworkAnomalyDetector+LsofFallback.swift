import Foundation

extension NetworkAnomalyDetector {

  /// Scan all system sockets via native proc_pidfdinfo (no shell-out).
  /// Used when the network extension is not running or for one-shot scans.
  public func scanCurrentConnections() async -> [NetworkAnomaly] {
    var anomalies: [NetworkAnomaly] = []
    let sockets = SocketEnumerator.enumerateAll()

    for entry in sockets {
      let ip = entry.remoteAddress
      let port = entry.remotePort
      guard !isPrivateIP(ip), !ip.isEmpty, ip != "0.0.0.0", ip != "::" else { continue }
      guard port > 0 else { continue }

      let protoName = entry.proto == Int32(IPPROTO_TCP) ? "tcp" : "udp"
      recordConnection(
        processName: entry.processName, pid: entry.pid,
        remoteAddress: ip, remotePort: port, protocol: protoName)

      if port > 1024 && isRawIP(ip) {
        anomalies.append(
          NetworkAnomaly(
            type: .rawIPConnection,
            processName: entry.processName,
            remoteAddress: "\(ip):\(port)",
            description: "\(entry.processName) [\(entry.pid)] connected to raw IP \(ip):\(port).",
            severity: .medium,
            connectionCount: 1,
            averageInterval: 0
          ))
      }

      if c2Ports.contains(port) {
        anomalies.append(
          NetworkAnomaly(
            type: .suspiciousPort,
            processName: entry.processName,
            remoteAddress: "\(ip):\(port)",
            description: "\(entry.processName) [\(entry.pid)] on known C2 port \(port).",
            severity: .high,
            connectionCount: 1,
            averageInterval: 0
          ))
      }
    }

    anomalies.append(contentsOf: detectBeaconing())
    return anomalies
  }
}
