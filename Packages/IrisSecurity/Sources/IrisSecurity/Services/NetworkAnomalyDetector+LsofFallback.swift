import Foundation

extension NetworkAnomalyDetector {

  /// Fallback: scan via lsof when network extension is not running.
  /// Uses -F pcn for machine-parseable output: p=pid, c=command, n=name.
  public func scanCurrentConnections() async -> [NetworkAnomaly] {
    var anomalies: [NetworkAnomaly] = []
    let output = await runLsof()

    var currentPid: pid_t = 0
    var currentProcess = ""

    for line in output.split(separator: "\n") {
      guard let prefix = line.first else { continue }
      let value = String(line.dropFirst())

      switch prefix {
      case "p":
        currentPid = pid_t(value) ?? 0
      case "c":
        currentProcess = value
      case "n":
        guard let (ip, port) = parseLsofName(value) else { continue }
        guard !isPrivateIP(ip), !ip.isEmpty, ip != "*" else { continue }

        recordConnection(
          processName: currentProcess, pid: currentPid,
          remoteAddress: ip, remotePort: port, protocol: "tcp")

        if port > 1024 && isRawIP(ip) {
          anomalies.append(
            NetworkAnomaly(
              type: .rawIPConnection,
              processName: currentProcess,
              remoteAddress: "\(ip):\(port)",
              description: "\(currentProcess) [\(currentPid)] connected to raw IP \(ip):\(port).",
              severity: .medium,
              connectionCount: 1,
              averageInterval: 0
            ))
        }

        if c2Ports.contains(port) {
          anomalies.append(
            NetworkAnomaly(
              type: .suspiciousPort,
              processName: currentProcess,
              remoteAddress: "\(ip):\(port)",
              description: "\(currentProcess) [\(currentPid)] on known C2 port \(port).",
              severity: .high,
              connectionCount: 1,
              averageInterval: 0
            ))
        }
      default:
        break
      }
    }

    anomalies.append(contentsOf: detectBeaconing())
    return anomalies
  }

  /// Parse lsof -F n value: "local:port->remote:port" or "host:port"
  func parseLsofName(_ name: String) -> (String, UInt16)? {
    guard let arrowRange = name.range(of: "->") else { return nil }
    let remote = String(name[arrowRange.upperBound...])
    guard let colonIdx = remote.lastIndex(of: ":") else { return nil }
    let ip = String(remote[remote.startIndex..<colonIdx])
    guard let port = UInt16(remote[remote.index(after: colonIdx)...]) else { return nil }
    let cleanIP =
      ip.hasPrefix("[") && ip.hasSuffix("]")
      ? String(ip.dropFirst().dropLast()) : ip
    return (cleanIP, port)
  }

  func runLsof() async -> String {
    await withCheckedContinuation { continuation in
      let process = Process()
      let pipe = Pipe()
      process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
      process.arguments = ["-i", "-P", "-n", "-F", "pcn"]
      process.standardOutput = pipe
      process.standardError = FileHandle.nullDevice
      do {
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
      } catch {
        continuation.resume(returning: "")
      }
    }
  }
}
